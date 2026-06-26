/**
 * sync-hagezi.js
 * Delete all Hagezi lists from Cloudflare Gateway Lists
 *
 * Run:
 * CF_ACCOUNT_ID=... CF_API_TOKEN=... node sync-hagezi.js
 */

const ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const API_TOKEN = process.env.CF_API_TOKEN;

const BASE_URL = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}`;

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

/**
 * Audit Error Detection:
 * Memastikan semua jenis error limitasi (Rate Limit HTTP 429, Kuota Akun, Limit Jumlah List, dll)
 * terdeteksi dengan akurat agar tidak menghentikan jalannya script secara paksa.
 */
function isRateLimitError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return /429|rate limit|too many requests|quota|limit reached|maximum number of lists|2017/i.test(msg);
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

async function deleteList(listId) {
  await cfFetch(`/rules/lists/${listId}`, "DELETE");
}

async function getAllPolicies() {
  const json = await cfFetch("/gateway/rules");
  return json.result || [];
}

async function deletePolicy(policyId) {
  await cfFetch(`/gateway/rules/${policyId}`, "DELETE");
}

async function main() {
  console.log("🗑️ Hagezi → Cloudflare Gateway - Delete All Lists\n");

  mustEnv("CF_ACCOUNT_ID");
  mustEnv("CF_API_TOKEN");

  console.log("📋 Step 1: Scan existing Hagezi lists...");
  const allLists = await getAllLists();
  const existingHagezi = allLists.filter((l) => String(l.name || "").startsWith("hagezi-"));
  
  console.log(`  Found Hagezi lists: ${existingHagezi.length}`);

  if (existingHagezi.length === 0) {
    console.log("  ℹ️ Tidak ada Hagezi list yang ditemukan. Proses dibatalkan.");
    return;
  }

  console.log("\n📋 Step 2: Scan existing Hagezi policies...");
  const allPolicies = await getAllPolicies();
  const hageziPolicies = allPolicies.filter((p) => 
    String(p.name || "").includes("Hagezi")
  );
  
  console.log(`  Found Hagezi policies: ${hageziPolicies.length}`);

  // ==========================================
  // STEP 3: DELETE HAGEZI POLICIES
  // ==========================================
  if (hageziPolicies.length > 0) {
    console.log("\n🔒 Step 3: Deleting Hagezi Policies...");
    for (const policy of hageziPolicies) {
      try {
        await deletePolicy(policy.id);
        console.log(`  ✅ Deleted policy: "${policy.name}" (ID: ${policy.id})`);
      } catch (err) {
        console.error(`  ❌ Failed to delete policy "${policy.name}": ${err.message}`);
      }
    }
  }

  // ==========================================
  // STEP 4: DELETE HAGEZI LISTS
  // ==========================================
  console.log("\n🗑️ Step 4: Deleting Hagezi Lists...");
  for (const list of existingHagezi) {
    try {
      await deleteList(list.id);
      console.log(`  ✅ Deleted list: "${list.name}" (ID: ${list.id})`);
    } catch (err) {
      console.error(`  ❌ Failed to delete list "${list.name}": ${err.message}`);
    }
  }

  console.log("\n🎉 Selesai! Semua Hagezi lists dan policies telah dihapus dari Cloudflare Gateway.");
}

main().catch((err) => {
  console.error("\n❌ Fatal Error:", err.message);
  process.exit(1);
});
