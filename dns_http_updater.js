/**
 * apply-hagezi-policies.js
 * Pindai daftar Zero Trust Gateway Lists ("hagezi-") yang sudah ada di akun Cloudflare,
 * lalu otomatis buat/update DNS Policy & HTTP Policy ke mode BLOCK.
 *
 * Diperbarui secara presisi berdasarkan Dokumentasi API Cloudflare Gateway:
 * - Menggunakan Endpoint Resmi: /gateway/lists dan /gateway/rules
 * - Menggunakan struktur Payload Gateway Rule yang valid.
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
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
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
    throw new Error(`CF API error pada ${method} ${path}: ${detail}`);
  }

  return json;
}

/**
 * Berdasarkan Dokumentasi Resmi Cloudflare Zero Trust:
 * Mengambil daftar list dengan memanggil GET /accounts/{account_id}/gateway/lists
 */
async function getGatewayLists() {
  const all = [];
  let page = 1;
  const per_page = 100;

  console.log("  [API] Mengambil daftar Zero Trust Gateway Lists...");
  while (true) {
    // Memanggil endpoint spesifik Gateway sesuai dokumentasi
    const json = await cfFetch(`/gateway/lists?per_page=${per_page}&page=${page}`);
    const result = json.result || [];
    all.push(...result);

    console.log(`  [API] Berhasil membaca ${result.length} list pada halaman ${page}.`);
    
    // Periksa pagination
    const info = json.result_info;
    if (!info || page >= info.total_pages || result.length < per_page) break;
    page += 1;
  }

  return all;
}

/**
 * Mengambil daftar aturan Gateway dengan memanggil GET /accounts/{account_id}/gateway/rules
 */
async function getGatewayPolicies() {
  const json = await cfFetch("/gateway/rules");
  return json.result || [];
}

/**
 * Membuat aturan Gateway baru dengan memanggil POST /accounts/{account_id}/gateway/rules
 */
async function createGatewayPolicy(payload) {
  const json = await cfFetch("/gateway/rules", "POST", payload);
  return json.result;
}

/**
 * Memperbarui aturan Gateway yang ada dengan memanggil PUT /accounts/{account_id}/gateway/rules/{rule_id}
 */
async function updateGatewayPolicy(policyId, updatedPolicy) {
  const payload = {
    name: updatedPolicy.name,
    description: updatedPolicy.description,
    action: updatedPolicy.action,
    enabled: updatedPolicy.enabled,
    traffic: updatedPolicy.traffic,
    filters: updatedPolicy.filters,
    precedence: updatedPolicy.precedence,
    rule_settings: updatedPolicy.rule_settings || {}
  };

  await cfFetch(`/gateway/rules/${policyId}`, "PUT", payload);
}

function buildClause(id, trafficKey) {
  return trafficKey === "dns"
    ? `any(dns.domains[*] in $${id})`
    : `any(http.request.domains[*] in $${id})`;
}

async function main() {
  console.log("🚀 Memulai Sinkronisasi Policy Cloudflare Gateway...\n");

  mustEnv("CF_ACCOUNT_ID");
  mustEnv("CF_API_TOKEN");

  // Step 1: Ambil semua list dari Zero Trust Gateway
  console.log("📋 Step 1: Memindai list di database Zero Trust Gateway...");
  const allLists = await getGatewayLists();
  
  console.log(`\n🔍 Total list yang ditemukan di Gateway: ${allLists.length}`);

  // Filter list yang tipenya adalah 'teams_list' atau 'hostname' dan mengandung nama 'hagezi'
  const hageziLists = allLists.filter((l) => {
    const nameLower = String(l.name || "").toLowerCase();
    return nameLower.includes("hagezi");
  });

  if (hageziLists.length === 0) {
    console.log("\n⚠️  DIAGNOSTIK:");
    console.log("   Daftar list kosong atau tidak ada yang mengandung nama 'hagezi'.");
    console.log("   Berikut adalah daftar 5 nama list teratas di akun Anda saat ini:");
    allLists.slice(0, 5).forEach(l => console.log(`   - "${l.name}" (ID: ${l.id})`));
    throw new Error("Tidak ditemukan list 'hagezi' di Zero Trust Gateway.");
  }

  console.log(`  ✅ Berhasil menyaring ${hageziLists.length} list Hagezi.`);
  const listIds = hageziLists.map(l => l.id);

  // Ambil semua policy saat ini
  const allPolicies = await getGatewayPolicies();

  // ==========================================
  // STEP 2: KONFIGURASI DNS POLICY (BLOCK)
  // ==========================================
  console.log("\n🔒 Step 2: Mengonfigurasi DNS Policy...");
  const dnsPolicyName = "Hagezi Blocklist - DNS";
  const dnsTrafficExpression = listIds.map(id => buildClause(id, "dns")).join(" or ");
  
  let dnsPolicy = allPolicies.find(p => p.name === dnsPolicyName);

  if (dnsPolicy) {
    console.log(`  🔄 Policy "${dnsPolicyName}" ditemukan. Memperbarui aturan...`);
    dnsPolicy.traffic = dnsTrafficExpression;
    dnsPolicy.action = "block";
    dnsPolicy.enabled = true;
    await updateGatewayPolicy(dnsPolicy.id, dnsPolicy);
    console.log("  ✅ DNS Policy sukses diperbarui!");
  } else {
    console.log(`  ✨ Policy "${dnsPolicyName}" tidak ditemukan. Membuat baru...`);
    await createGatewayPolicy({
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
  // STEP 3: KONFIGURASI HTTP POLICY (BLOCK)
  // ==========================================
  console.log("\n🌐 Step 3: Mengonfigurasi HTTP Policy...");
  const httpPolicyName = "Hagezi Blocklist - HTTP";
  const httpTrafficExpression = listIds.map(id => buildClause(id, "http")).join(" or ");

  let httpPolicy = allPolicies.find(p => p.name === httpPolicyName);

  if (httpPolicy) {
    console.log(`  🔄 Policy "${httpPolicyName}" ditemukan. Memperbarui aturan...`);
    httpPolicy.traffic = httpTrafficExpression;
    httpPolicy.action = "block";
    httpPolicy.enabled = true;
    await updateGatewayPolicy(httpPolicy.id, httpPolicy);
    console.log("  ✅ HTTP Policy sukses diperbarui!");
  } else {
    console.log(`  ✨ Policy "${httpPolicyName}" tidak ditemukan. Membuat baru...`);
    await createGatewayPolicy({
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

  console.log("\n🎉 Selesai! DNS & HTTP Policy di Cloudflare Gateway sekarang sepenuhnya aktif.");
}

main().catch((err) => {
  console.error("\n❌ Error:", err.message);
  process.exit(1);
});
