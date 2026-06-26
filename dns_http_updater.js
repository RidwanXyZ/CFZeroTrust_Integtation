/**
 * apply-hagezi-policies.js
 * SCRIPT SINKRONISASI POLICY GATEWAY CLOUDFLARE
 *
 * Diperbarui secara presisi berdasarkan Skema API Cloudflare Zero Trust:
 * - Mengambil list dari: /gateway/lists
 * - Mengelola policy/rules melalui endpoint resmi: /gateway/rules
 * - Mengirimkan payload PUT/POST yang valid (meliputi schedule, identity, device_posture, dll.)
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
  
  console.log(`  [Fetch] ${method} ke: ${path}`);

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

  console.log("  [API] Mengambil daftar list dari /gateway/lists...");
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
 * Mendapatkan seluruh rules melalui endpoint resmi: GET /gateway/rules
 */
async function getGatewayPolicies() {
  const json = await cfFetch("/gateway/rules");
  return json.result || [];
}

/**
 * Membuat rule baru melalui endpoint resmi: POST /gateway/rules
 * Payload disesuaikan agar menyertakan parameter wajib identity dan device_posture
 */
async function createGatewayPolicy(payload) {
  const finalPayload = {
    name: payload.name,
    description: payload.description,
    action: payload.action,
    enabled: payload.enabled,
    traffic: payload.traffic,
    filters: payload.filters,
    precedence: payload.precedence,
    identity: payload.identity || "",
    device_posture: payload.device_posture || "",
    rule_settings: payload.rule_settings || {}
  };

  // Kirim schedule jika didefinisikan saat pembuatan
  if (payload.schedule) {
    finalPayload.schedule = payload.schedule;
  }

  const json = await cfFetch("/gateway/rules", "POST", finalPayload);
  return json.result;
}

/**
 * Memperbarui rule lama melalui endpoint resmi: PUT /gateway/rules/{rule_id}
 * Diperbarui: Memetakan struktur schedule, identity, device_posture, dan expiration asli
 * agar tidak rusak atau hilang saat melakukan update PUT.
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
    identity: updatedPolicy.identity || "",
    device_posture: updatedPolicy.device_posture || "",
    rule_settings: updatedPolicy.rule_settings || {}
  };

  // Pertahankan konfigurasi schedule jika ada pada objek yang di-get sebelumnya
  if (updatedPolicy.schedule) {
    payload.schedule = updatedPolicy.schedule;
  }

  // Pertahankan konfigurasi expiration (untuk DNS Policy timed-out) jika ada
  if (updatedPolicy.expiration) {
    payload.expiration = updatedPolicy.expiration;
  }

  await cfFetch(`/gateway/rules/${policyId}`, "PUT", payload);
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
  
  if (allLists.length === 0) {
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

  console.log(`✅ Berhasil menyaring ${hageziLists.length} list Hagezi.`);
  const listIds = hageziLists.map(l => l.id);

  // Ambil semua policy saat ini secara konsisten dari /gateway/rules
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
