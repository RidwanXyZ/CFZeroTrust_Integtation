
/**
 * apply-hagezi-policies.js
 * Pindai daftar list "hagezi-" yang sudah ada di Cloudflare Gateway,
 * lalu otomatis buat/update DNS Policy & HTTP Policy ke mode BLOCK.
 *
 * Script ini TIDAK mendownload file dari internet ataupun membuat list baru,
 * sehingga sangat aman dari limitasi pembuatan list (Error 2017).
 *
 * Run:
 * CF_ACCOUNT_ID=... CF_API_TOKEN=... node apply-hagezi-policies.js
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

async function getAllPolicies() {
  const json = await cfFetch("/gateway/rules");
  return json.result || [];
}

async function createPolicy(payload) {
  const json = await cfFetch("/gateway/rules", "POST", payload);
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

function buildClause(id, trafficKey) {
  return trafficKey === "dns"
    ? `any(dns.domains[*] in $${id})`
    : `any(http.request.domains[*] in $${id})`;
}

async function main() {
  console.log("🚀 Memulai Pembuatan & Sinkronisasi Policy Gateway Cloudflare...\n");

  mustEnv("CF_ACCOUNT_ID");
  mustEnv("CF_API_TOKEN");

  // Step 1: Ambil semua list yang berawalan dengan "hagezi-"
  console.log("📋 Step 1: Memindai list Hagezi yang sudah ada di akun Cloudflare...");
  const allLists = await getAllLists();
  const hageziLists = allLists.filter((l) => String(l.name || "").startsWith("hagezi-"));

  if (hageziLists.length === 0) {
    throw new Error("Tidak ditemukan list dengan nama berawalan 'hagezi-' di akun Cloudflare kamu. Silakan buat list terlebih dahulu.");
  }

  console.log(`  ✅ Ditemukan ${hageziLists.length} list Hagezi siap pakai.`);

  const listIds = hageziLists.map(l => l.id);

  // Ambil semua policy yang ada di Cloudflare saat ini
  const allPolicies = await getAllPolicies();

  // ==========================================
  // STEP 2: TERAPKAN KE DNS POLICY (BLOCK)
  // ==========================================
  console.log("\n🔒 Step 2: Mengonfigurasi DNS Policy...");
  const dnsPolicyName = "Hagezi Blocklist - DNS";
  const dnsTrafficExpression = listIds.map(id => buildClause(id, "dns")).join(" or ");
  
  // Cari apakah policy DNS Hagezi sudah ada
  let dnsPolicy = allPolicies.find(p => p.name === dnsPolicyName);

  if (dnsPolicy) {
    console.log(`  🔄 Policy "${dnsPolicyName}" ditemukan. Memperbarui aturan blokir...`);
    dnsPolicy.traffic = dnsTrafficExpression;
    dnsPolicy.action = "block";
    dnsPolicy.enabled = true;
    await updatePolicy(dnsPolicy.id, dnsPolicy);
    console.log("  ✅ DNS Policy sukses diperbarui!");
  } else {
    console.log(`  ✨ Policy "${dnsPolicyName}" tidak ditemukan. Membuat policy baru...`);
    await createPolicy({
      name: dnsPolicyName,
      description: "Auto-generated policy to block Hagezi lists",
      action: "block",
      enabled: true,
      traffic: dnsTrafficExpression,
      filters: ["dns"],
      precedence: 1000
    });
    console.log("  ✅ DNS Policy baru berhasil dibuat dengan action BLOCK!");
  }

  // ==========================================
  // STEP 3: TERAPKAN KE HTTP POLICY (BLOCK)
  // ==========================================
  console.log("\n🌐 Step 3: Mengonfigurasi HTTP Policy...");
  const httpPolicyName = "Hagezi Blocklist - HTTP";
  const httpTrafficExpression = listIds.map(id => buildClause(id, "http")).join(" or ");

  // Cari apakah policy HTTP Hagezi sudah ada
  let httpPolicy = allPolicies.find(p => p.name === httpPolicyName);

  if (httpPolicy) {
    console.log(`  🔄 Policy "${httpPolicyName}" ditemukan. Memperbarui aturan blokir...`);
    httpPolicy.traffic = httpTrafficExpression;
    httpPolicy.action = "block";
    httpPolicy.enabled = true;
    await updatePolicy(httpPolicy.id, httpPolicy);
    console.log("  ✅ HTTP Policy sukses diperbarui!");
  } else {
    console.log(`  ✨ Policy "${httpPolicyName}" tidak ditemukan. Membuat policy baru...`);
    await createPolicy({
      name: httpPolicyName,
      description: "Auto-generated policy to block Hagezi lists via HTTP Inspection",
      action: "block",
      enabled: true,
      traffic: httpTrafficExpression,
      filters: ["http"],
      precedence: 1000
    });
    console.log("  ✅ HTTP Policy baru berhasil dibuat dengan action BLOCK!");
  }

  console.log("\n🎉 Selesai! DNS Policy dan HTTP Policy sekarang telah aktif memblokir semua list Hagezi di Cloudflare Gateway kamu.");
}

main().catch((err) => {
  console.error("\n❌ Error:", err.message);
  process.exit(1);
});
