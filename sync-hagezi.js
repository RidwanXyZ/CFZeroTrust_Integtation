
/**
 * sync-hagezi.js
 * Fetch Hagezi lists → auto-split per 1000 → upsert to Cloudflare Gateway Lists
 * lalu update DNS & HTTP Policy tanpa restart dari awal kalau kena limit.
 *
 * Run:
 * CF_ACCOUNT_ID=... CF_API_TOKEN=... CF_DNS_POLICY_ID=... CF_HTTP_POLICY_ID=... node sync-hagezi.js
 */

const ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const API_TOKEN = process.env.CF_API_TOKEN;
const DNS_POLICY_ID = process.env.CF_DNS_POLICY_ID;
const HTTP_POLICY_ID = process.env.CF_HTTP_POLICY_ID;

const BASE_URL = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}`;
const STATE_FILE = "./.sync-hagezi-state.json";

const HAGEZI_LISTS = [
  {
    name: "hagezi-pro-plus",
    url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.plus.txt",
    description: "Hagezi Pro Plus - Ads, Tracking, Analytics, Smart TV telemetry",
  },
  {
    name: "hagezi-gambling",
    url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/gambling.txt",
    description: "Hagezi Gambling - Situs judi online",
  },
  {
    name: "hagezi-porn",
    url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/porn.txt",
    description: "Hagezi Porn - Konten dewasa",
  },
  {
    name: "hagezi-threat",
    url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/threat.txt",
    description: "Hagezi Threat - Malware, Phishing, Ransomware",
  },
];

// Keep safe for Cloudflare list item limits.
const CHUNK_SIZE = 1000;

function mustEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing env: ${name}`);
  return value;
}

function cfHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${API_TOKEN}`,
  };
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRateLimitError(err) {
  const msg = String(err?.message || err);
  // PERBAIKAN: Menambahkan "2017" dan "maximum number of lists reached" ke dalam deteksi error
  return /429|rate limit|too many requests|quota|maximum number of lists reached|2017/i.test(msg);
}

async function cfFetch(path, method = "GET", body = null) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: cfHeaders(),
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

  let json = null;
  try {
    json = await res.json();
  } catch (_) {
    // ignore
  }

  if (!res.ok || json?.success === false) {
    const detail =
      json?.errors?.length
        ? JSON.stringify(json.errors)
        : json?.messages?.length
          ? JSON.stringify(json.messages)
          : `${res.status} ${res.statusText}`;
    throw new Error(`CF API error on ${method} ${path}: ${detail}`);
  }

  return json;
}

function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) chunks.push(arr.slice(i, i + size));
  return chunks;
}

function unique(arr) {
  return [...new Set(arr)];
}

async function fetchDomains(url) {
  console.log(`  Fetching ${url} ...`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);

  const text = await res.text();
  const domains = text
    .split("\n")
    .map((l) => l.trim().toLowerCase())
    .filter((l) => l && !l.startsWith("#") && !l.startsWith("!") && l.includes("."));

  return unique(domains);
}

function listItemFromDomain(domain) {
  return {
    hostname: {
      url_hostname: domain,
      exclude_exact_hostname: false,
    },
    comment: "Synced from Hagezi",
  };
}

function buildClause(id, trafficKey) {
  return trafficKey === "dns"
    ? `any(dns.domains[*] in $${id})`
    : `any(http.request.domains[*] in $${id})`;
}

function stripOldHageziClauses(traffic, oldListIds, trafficKey) {
  const source = String(traffic || "").trim();
  if (!source || !oldListIds?.length) return source;

  const parts = source.split(/\s+or\s+/);
  const selectorHint = trafficKey === "dns" ? "dns.domains[*]" : "http.request.domains[*]";

  const filtered = parts.filter((part) => {
    return !oldListIds.some((id) => part.includes(`$${id}`) && part.includes(selectorHint));
  });

  return filtered.join(" or ").replace(/\s+/g, " ").trim();
}

function injectListIds(policy, newListIds, trafficKey, oldListIds = []) {
  const updatedPolicy = JSON.parse(JSON.stringify(policy));
  const baseTraffic = stripOldHageziClauses(updatedPolicy.traffic || "", oldListIds, trafficKey);
  const uniqueNewIds = unique(newListIds.filter(Boolean));

  const newConditions = uniqueNewIds.map((id) => buildClause(id, trafficKey));
  const appended = newConditions.join(" or ");

  updatedPolicy.traffic = baseTraffic
    ? `(${baseTraffic}) or ${appended}`
    : appended;

  return updatedPolicy;
}

async function getAllLists() {
  const all = [];
  let page = 1;
  const per_page = 100;

  while (true) {
    const json = await cfFetch(`/rules/lists?per_page=${per_page}&page=${page}`);
    const result = json.result || [];
    all.push(...result);

    const info = json.result_info;
    if (!info || page >= info.total_pages) break;
    page += 1;
  }

  return all;
}

async function deleteList(id, name) {
  await cfFetch(`/rules/lists/${id}`, "DELETE");
  console.log(`  🗑 Deleted old list: ${name} (${id})`);
}

async function createList(name, description, domains) {
  const createJson = await cfFetch("/rules/lists", "POST", {
    kind: "hostname",
    name,
    description,
  });

  const listId = createJson.result.id;
  const items = domains.map(listItemFromDomain);

  if (items.length > 0) {
    const itemsJson = await cfFetch(`/rules/lists/${listId}/items`, "POST", items);

    const operationId =
      itemsJson.result?.operation_id ||
      itemsJson.result?.id ||
      itemsJson.result?.operation?.id;

    if (operationId) {
      await waitForBulkOperation(operationId);
    }
  }

  return listId;
}

async function waitForBulkOperation(operationId) {
  for (let i = 0; i < 60; i++) {
    const json = await cfFetch(`/rules/lists/bulk_operations/${operationId}`);
    const status = json.result?.status;

    if (status === "completed") return json.result;
    if (status === "failed") {
      throw new Error(`Bulk operation failed: ${json.result?.error || "unknown error"}`);
    }

    await sleep(2000);
  }

  throw new Error(`Bulk operation timeout: ${operationId}`);
}

async function getPolicy(policyId) {
  const json = await cfFetch(`/gateway/rules/${policyId}`);
  return json.result;
}

async function updatePolicy(policyId, updatedPolicy) {
  const payload = {
    name: updatedPolicy.name,
    description: updatedPolicy.description,
    action: updatedPolicy.action,
    enabled: updatedPolicy.enabled,
    traffic: updatedPolicy.traffic,
    filters: updatedPolicy.filters,
    precedence: updatedPolicy.precedence,
  };

  await cfFetch(`/gateway/rules/${policyId}`, "PUT", payload);
}

function groupExistingListsByName(allLists) {
  const map = new Map();
  for (const item of allLists) {
    if (item?.name && item?.id) map.set(item.name, item.id);
  }
  return map;
}

async function main() {
  console.log("🚀 Hagezi → Cloudflare Gateway Sync\n");

  mustEnv("CF_ACCOUNT_ID");
  mustEnv("CF_API_TOKEN");
  mustEnv("CF_DNS_POLICY_ID");
  mustEnv("CF_HTTP_POLICY_ID");

  console.log("📋 Step 1: Scan existing Hagezi lists...");
  const allLists = await getAllLists();
  const existingHagezi = allLists.filter((l) => String(l.name || "").startsWith("hagezi-"));
  const existingByName = groupExistingListsByName(existingHagezi);
  
  // Ambil semua ID list Hagezi lama untuk dibersihkan dari rule policy nanti
  const allOldListIds = existingHagezi.map(l => l.id);

  console.log(`  Existing Hagezi lists: ${existingHagezi.length}`);

  const allNewListIds = [];
  let creationHitLimit = false;

  console.log("\n📥 Step 2: Fetch & upsert Hagezi lists...");
  for (const hagezi of HAGEZI_LISTS) {
    console.log(`\n▶ Processing: ${hagezi.name}`);

    const domains = await fetchDomains(hagezi.url);
    console.log(`  Total domains: ${domains.length.toLocaleString()}`);

    const chunks = chunkArray(domains, CHUNK_SIZE);
    console.log(`  Split jadi ${chunks.length} list(s)`);

    for (let i = 0; i < chunks.length; i++) {
      const listName = chunks.length === 1
        ? hagezi.name
        : `${hagezi.name}-${String(i + 1).padStart(3, "0")}`;

      const existingId = existingByName.get(listName);
      if (existingId) {
        allNewListIds.push(existingId);
        console.log(`  ↩ Reuse existing: ${listName} → ID: ${existingId}`);
        continue;
      }

      try {
        const id = await createList(listName, hagezi.description, chunks[i]);
        allNewListIds.push(id);
        existingByName.set(listName, id);
        console.log(`  ✅ Created: ${listName} (${chunks[i].length} domains) → ID: ${id}`);
      } catch (err) {
        if (isRateLimitError(err)) {
          console.log("  ⚠ Kuota list Cloudflare tercapai! Menghentikan pembuatan list baru dan lanjut update policy.");
          creationHitLimit = true;
          break;
        }
        throw err;
      }
    }

    if (creationHitLimit) break;
  }

  if (allNewListIds.length === 0) {
    throw new Error("No Hagezi list IDs available. Policy update skipped.");
  }

  console.log(`\n📊 List ID ready: ${allNewListIds.length}`);

  // Update DNS Policy
  console.log("\n🔒 Step 3: Update DNS Policy...");
  const dnsPolicy = await getPolicy(DNS_POLICY_ID);
  console.log(`  Policy: "${dnsPolicy.name}"`);
  console.log(`  Traffic expression sebelum:\n  ${dnsPolicy.traffic}`);

  // PERBAIKAN: Melempar allOldListIds agar tidak terjadi duplikasi clause or
  const updatedDns = injectListIds(dnsPolicy, allNewListIds, "dns", allOldListIds);
  await updatePolicy(DNS_POLICY_ID, updatedDns);
  console.log("  ✅ DNS Policy updated!");

  // Update HTTP Policy
  console.log("\n🌐 Step 4: Update HTTP Policy...");
  const httpPolicy = await getPolicy(HTTP_POLICY_ID);
  console.log(`  Policy: "${httpPolicy.name}"`);
  console.log(`  Traffic expression sebelum:\n  ${httpPolicy.traffic}`);

  // PERBAIKAN: Melempar allOldListIds agar tidak terjadi duplikasi clause or
  const updatedHttp = injectListIds(httpPolicy, allNewListIds, "http", allOldListIds);
  await updatePolicy(HTTP_POLICY_ID, updatedHttp);
  console.log("  ✅ HTTP Policy updated!");

  console.log("\n🎉 Sync selesai! Semua list Hagezi yang berhasil diproses telah dipush ke Cloudflare Gateway.");
}

main().catch((err) => {
  console.error("\n❌ Error:", err.message);
  process.exit(1);
});
