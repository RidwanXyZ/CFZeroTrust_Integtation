/**
 * apply-hagezi-policies.js
 * SCRIPT DIAGNOSTIK & SINKRONISASI POLICY GATEWAY CLOUDFLARE
 *
 * Script ini dirancang khusus untuk mencari tahu mengapa list Cloudflare Anda 
 * tidak terbaca oleh API, sekaligus menerapkan policy jika berhasil terhubung.
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

  console.log("  [API] Mencoba menarik data list dari endpoint resmi Gateway...");
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

async function getAllPolicies() {
  const json = await cfFetch("/gateway/rules");
  return json.result || [];
}

async function createGatewayPolicy(payload) {
  const json = await cfFetch("/gateway/rules", "POST", payload);
  return json.result;
}

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
  console.log("🚀 MEMULAI PROSES DIAGNOSTIK & SYNC GATEWAY CLOUDFLARE...\n");

  mustEnv("CF_ACCOUNT_ID");
  mustEnv("CF_API_TOKEN");

  // Cetak 6 karakter pertama token untuk memastikan token terisi dengan benar (bukan kosong atau salah format)
  console.log(`⚙️  Verifikasi Konfigurasi:`);
  console.log(`   - Account ID: ${ACCOUNT_ID}`);
  console.log(`   - API Token : ${API_TOKEN ? `${API_TOKEN.substring(0, 6)}...` : "TIDAK TERDETEKSI"}`);

  let allLists = [];
  try {
    allLists = await getGatewayLists();
  } catch (err) {
    console.log("\n❌ DIAGNOSTIK: Cloudflare menolak akses pemanggilan list!");
    console.log(`   Detail Error: ${err.message}`);
    console.log("\n💡 SOLUSI:");
    console.log("   1. Pastikan Account ID di atas sudah persis sama dengan yang ada di URL dashboard Anda.");
    console.log("   2. Pastikan API Token Anda memiliki hak akses 'Zero Trust' dan 'Lists'.");
    console.log("      Cara verifikasi token: Masuk ke Cloudflare Dashboard > My Profile > API Tokens.");
    console.log("      Edit token Anda dan tambahkan izin: 'Account' > 'Zero Trust' > 'Edit'.\n");
    throw err;
  }
  
  console.log(`\n🔍 Total list yang ditemukan di Gateway: ${allLists.length}`);
  
  if (allLists.length > 0) {
    console.log("📋 Daftar 5 List Pertama yang berhasil dideteksi oleh API:");
    allLists.slice(0, 5).forEach((l, idx) => {
      console.log(`   [${idx + 1}] Nama: "${l.name}" | ID: ${l.id} | Tipe: ${l.type || l.kind}`);
    });
  } else {
    console.log("\n⚠️  DIAGNOSTIK: API berhasil terhubung, tetapi mengembalikan 0 list.");
    console.log("   Artinya API Token Anda valid, namun diarahkan ke akun yang kosong, atau");
    console.log("   akun Anda belum memiliki list sama sekali di menu Zero Trust > Reusable Components.");
    throw new Error("Tidak ada list yang terdeteksi.");
  }

  // Filter list yang mengandung kata "hagezi" (Case-Insensitive)
  const hageziLists = allLists.filter((l) => {
    const nameLower = String(l.name || "").toLowerCase();
    return nameLower.includes("hagezi");
  });

  if (hageziLists.length === 0) {
    console.log("\n⚠️  DIAGNOSTIK:");
    console.log("   List berhasil dibaca dari API, tetapi tidak ada yang mengandung nama 'hagezi'.");
    console.log("   Silakan ganti nama list Anda di dashboard agar mengandung kata 'hagezi' atau");
    console.log("   sesuaikan kata kunci penyaring di script ini.");
    throw new Error("Tidak ditemukan list 'hagezi' di Zero Trust Gateway.");
  }

  console.log(`\n✅ Berhasil menyaring ${hageziLists.length} list Hagezi.`);
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
