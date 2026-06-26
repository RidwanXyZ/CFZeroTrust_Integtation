/**
 * sync-hagezi.js
 * Fetch Hagezi lists → auto-split per 1000 → push ke Cloudflare Gateway Lists
 * lalu append semua list ID baru ke DNS & HTTP Policy yang existing.
 */

const ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const API_TOKEN  = process.env.CF_API_TOKEN;
const DNS_POLICY_ID  = process.env.CF_DNS_POLICY_ID;
const HTTP_POLICY_ID = process.env.CF_HTTP_POLICY_ID;

const BASE_URL = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway`;

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

const CHUNK_SIZE = 1000000;

// ── Helpers ──────────────────────────────────────────────────────────────────

function cfHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${API_TOKEN}`,
  };
}

async function cfFetch(path, method = "GET", body = null) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: cfHeaders(),
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const json = await res.json();
  if (!json.success) throw new Error(`CF API error on ${method} ${path}: ${JSON.stringify(json.errors)}`);
  return json;
}

/** Fetch & parse domain list — skip comments dan baris kosong */
async function fetchDomains(url) {
  console.log(`  Fetching ${url} ...`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
  const text = await res.text();
  return text
    .split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#") && !l.startsWith("!") && l.includes("."));
}

/** Split array jadi chunks */
function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) chunks.push(arr.slice(i, i + size));
  return chunks;
}

// ── Gateway List operations ───────────────────────────────────────────────────

/** Ambil semua existing lists */
async function getAllLists() {
  const json = await cfFetch("/lists");
  return json.result || [];
}

/** Hapus list by ID */
async function deleteList(id, name) {
  await cfFetch(`/lists/${id}`, "DELETE");
  console.log(`  🗑  Deleted old list: ${name} (${id})`);
}

/** Buat list baru */
async function createList(name, description, domains) {
  const items = domains.map(d => ({ value: d }));
  const json = await cfFetch("/lists", "POST", {
    name,
    description,
    type: "DOMAIN",
    items,
  });
  return json.result.id;
}

// ── Policy operations ─────────────────────────────────────────────────────────

async function getPolicy(type, policyId) {
  const json = await cfFetch(`/${type}/rules/${policyId}`);
  return json.result;
}

/**
 * Append list IDs ke rule block yang existing.
 * Cari traffic condition bertipe "any" yang sudah ada,
 * lalu inject list IDs baru ke dalamnya.
 */
function injectListIds(policy, newListIds, trafficKey) {
  const updatedPolicy = JSON.parse(JSON.stringify(policy)); // deep clone

  // Cari kondisi block di traffic
  const traffic = updatedPolicy.traffic || "";

  // Build tambahan kondisi list
  // Format CF expression: any(dns.domains[*] in $list_id) untuk DNS
  //                       any(http.request.domains[*] in $list_id) untuk HTTP
  const prefix = trafficKey === "dns"
    ? "any(dns.domains[*] in $"
    : "any(http.request.domains[*] in $";

  const newConditions = newListIds.map(id => `${prefix}${id.replace(/-/g, "")})`);

  // Append ke traffic expression yang existing
  const appended = newConditions.join(" or ");
  updatedPolicy.traffic = traffic
    ? `(${traffic}) or ${appended}`
    : appended;

  return updatedPolicy;
}

async function updatePolicy(type, policyId, updatedPolicy) {
  // Cloudflare hanya butuh field tertentu saat update
  const payload = {
    name:        updatedPolicy.name,
    description: updatedPolicy.description,
    action:      updatedPolicy.action,
    enabled:     updatedPolicy.enabled,
    traffic:     updatedPolicy.traffic,
    filters:     updatedPolicy.filters,
  };
  await cfFetch(`/${type}/rules/${policyId}`, "PUT", payload);
}

// ── Cleanup old hagezi lists ──────────────────────────────────────────────────

async function cleanupOldLists(allLists) {
  const oldLists = allLists.filter(l => l.name.startsWith("hagezi-"));
  if (oldLists.length === 0) {
    console.log("  Tidak ada list Hagezi lama yang perlu dihapus.");
    return;
  }
  for (const l of oldLists) {
    await deleteList(l.id, l.name);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log("🚀 Hagezi → Cloudflare Gateway Sync\n");

  // Validasi env
  for (const key of ["CF_ACCOUNT_ID", "CF_API_TOKEN", "CF_DNS_POLICY_ID", "CF_HTTP_POLICY_ID"]) {
    if (!process.env[key]) throw new Error(`Missing env: ${key}`);
  }

  // 1. Hapus list Hagezi lama
  console.log("📋 Step 1: Cleanup existing Hagezi lists...");
  const allLists = await getAllLists();
  await cleanupOldLists(allLists);

  // 2. Fetch & push list baru
  console.log("\n📥 Step 2: Fetch & create new lists...");
  const allNewListIds = [];

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

      const id = await createList(listName, hagezi.description, chunks[i]);
      allNewListIds.push(id);
      console.log(`  ✅ Created: ${listName} (${chunks[i].length} domains) → ID: ${id}`);
    }
  }

  console.log(`\n📊 Total lists created: ${allNewListIds.length}`);

  // 3. Update DNS Policy
  console.log("\n🔒 Step 3: Update DNS Policy...");
  const dnsPolicy = await getPolicy("dns", DNS_POLICY_ID);
  console.log(`  Policy: "${dnsPolicy.name}"`);
  console.log(`  Traffic expression sebelum:\n  ${dnsPolicy.traffic}`);
  const updatedDns = injectListIds(dnsPolicy, allNewListIds, "dns");
  await updatePolicy("dns", DNS_POLICY_ID, updatedDns);
  console.log("  ✅ DNS Policy updated!");

  // 4. Update HTTP Policy
  console.log("\n🌐 Step 4: Update HTTP Policy...");
  const httpPolicy = await getPolicy("http", HTTP_POLICY_ID);
  console.log(`  Policy: "${httpPolicy.name}"`);
  console.log(`  Traffic expression sebelum:\n  ${httpPolicy.traffic}`);
  const updatedHttp = injectListIds(httpPolicy, allNewListIds, "http");
  await updatePolicy("http", HTTP_POLICY_ID, updatedHttp);
  console.log("  ✅ HTTP Policy updated!");

  console.log("\n🎉 Sync selesai! Semua list Hagezi berhasil dipush ke Cloudflare Gateway.");
}

main().catch(err => {
  console.error("\n❌ Error:", err.message);
  process.exit(1);
});
