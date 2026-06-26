/**
 * apply-hagezi-policies.js
 * SCRIPT DIAGNOSTIK & SINKRONISASI POLICY GATEWAY CLOUDFLARE
 *
 * Diperbarui secara presisi berdasarkan API Cloudflare Zero Trust:
 * - Mengambil list dari: /gateway/lists
 * - Mengelola policy/rules melalui endpoint resmi: /teams/rules
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
  
  // LOG KEAMANAN: Memastikan pemanggilan URL sudah benar
  console.log(`  [Fetch Debug] ${method} ke: ${url.replace(API_TOKEN, "HIDDEN_TOKEN")}`);

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

async function getGatewayLists() {
  const all = [];
  let page = 1;
  const per_page = 100;

  console.log("  [API] Mencari data list dari endpoint Gateway...");
  while (true) {
    const json = await cfFetch(`/gateway/lists?per_page=${per_page}&page=${page}`);
    const result = json.result || [];
    all.push(...result);

    console.log(`  [API] Halaman ${page}: Berhasil membaca ${result.length} list.`);
    
    const info = json.result_info;
    if (!info || page >= info.total_pages || result.length < per_page) break;
    page += 1;
  }

  return all;
}

/**
 * Berdasarkan API resmi Cloudflare Teams/Gateway:
 * Mengambil daftar policy menggunakan endpoint: GET /accounts/{account_id}/teams/rules
 */
async function getGatewayPolicies() {
  const json = await cfFetch("/teams/rules");
  return json.result || [];
}

/**
 * Membuat policy baru menggunakan endpoint: POST /accounts/{account_id}/teams/rules
 */
async function createGatewayPolicy(payload) {
  const json = await cfFetch("/teams/rules", "POST", payload);
  return json.result;
}

/**
 * Memperbarui policy menggunakan endpoint: PUT /accounts/{account_id}/teams/rules/{rule_id}
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

  await cfFetch(`/teams/rules/${policyId}`, "PUT", payload);
}

function buildClause(id, trafficKey) {
  return trafficKey === "dns"
    ? `any(dns.domains[*] in $${id})`
    : `any(http.request.domains[*] in $${id})`;
}

async function main() {
  console.log("🚀 MEMULAI PROSES SYNC GATEWAY CLOUDFLARE...\n");

  mustEnv("CF_ACCOUNT_ID");
  mustEnv("CF_API_TOKEN");

  // Verifikasi Konfigurasi awal
  console.log(`⚙️  Verifikasi Konfigurasi:`);
  console.log(`   - Account ID: ${ACCOUNT_ID}`);
  console.log(`   - API Token : ${API_TOKEN ? `${API_TOKEN.substring(0, 6)}...` : "TIDAK TERDETEKSI"}`);

  let allLists = [];
  try {
    allLists = await getGatewayLists();
  } catch (err) {
    console.log("\n❌ DIAGNOSTIK: Cloudflare menolak akses pemanggilan list!");
    console.log(`   Detail Error: ${err.message}`);
    throw err;
  }
  
  console.log(`\n🔍 Total list yang ditemukan di Gateway: ${allLists.length}`);
  
  if (allLists.length > 0) {
    console.log("📋 Daftar 5 List Pertama yang berhasil dideteksi oleh API:");
    allLists.slice(0, 5).forEach((l, idx) => {
      console.log(`   [${idx + 1}] Nama: "${l.name}" | ID: ${l.id} | Tipe: ${l.type || l.kind}`);
    });
  } else {
    throw new Error("Tidak ada list yang terdeteksi di akun Anda.");
  }

  // Filter list yang mengandung kata "hagezi" (Case-Insensitive)
  const hageziLists = allLists.filter((l) => {
    const nameLower = String(l.name || "").toLowerCase();
    return nameLower.includes("hagezi");
  });

  if (hageziLists.length === 0) {
    throw new Error("Tidak ditemukan list 'hagezi' di Zero Trust Gateway.");
  }

  console.log(`\n✅ Berhasil menyaring ${hageziLists.length} list Hagezi.`);
  const listIds = hageziLists.map(l => l.id);

  // Ambil semua policy saat ini melalui endpoint resmi /teams/rules
  const allPolicies = await getGatewayPolicies();

  // ====================================================================
  // MENENTUKAN PRECEDENCE (PRIORITAS) UNIK SECARA DINAMIS
  // ====================================================================
  const existingPrecedences = allPolicies.map(p => p.precedence || 0);
  const maxPrecedence = existingPrecedences.length > 0 ? Math.max(...existingPrecedences) : 1000;
  
  const dnsPrecedenceValue = maxPrecedence + 10;
  const httpPrecedenceValue = maxPrecedence + 20;

  console.log(`\n🛡️  Auto-Precedence:`);
  console.log(`   - Precedence tertinggi saat ini : ${maxPrecedence}`);
  console.log(`   - Precedence yang akan dialokasikan untuk DNS : ${dnsPrecedenceValue}`);
  console.log(`   - Precedence yang akan dialokasikan untuk HTTP: ${httpPrecedenceValue}`);

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
    console.log(`  ✨ Policy "${dnsPolicyName}" tidak ditemukan. Membuat baru dengan precedence ${dnsPrecedenceValue}...`);
    await createGatewayPolicy({
      name: dnsPolicyName,
      description: "Auto-generated policy to block Hagezi lists",
      action: "block",
      enabled: true,
      traffic: dnsTrafficExpression,
      filters: ["dns"],
      precedence: dnsPrecedenceValue
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
    console.log(`  ✨ Policy "${httpPolicyName}" tidak ditemukan. Membuat baru dengan precedence ${httpPrecedenceValue}...`);
    await createGatewayPolicy({
      name: httpPolicyName,
      description: "Auto-generated policy to block Hagezi lists via HTTP Inspection",
      action: "block",
      enabled: true,
      traffic: httpTrafficExpression,
      filters: ["http"],
      precedence: httpPrecedenceValue
    });
    console.log("  ✅ HTTP Policy baru berhasil dibuat dengan action BLOCK!");
  }

  console.log("\n🎉 Selesai! DNS & HTTP Policy di Cloudflare Gateway sekarang sepenuhnya aktif.");
}

main().catch((err) => {
  console.error("\n❌ Error:", err.message);
  process.exit(1);
});
