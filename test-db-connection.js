// TANI (DEBUG) SCRIPT'İ — sorunu bulduktan sonra bu dosyayı silebilirsiniz.
// Şifreyi hiçbir zaman ekrana yazdırmaz; sadece bağlantı string'inin doğru
// parçalanıp parçalanmadığını ve gerçek bağlantının başarılı olup olmadığını gösterir.
require('dotenv').config();
const { Pool } = require('pg');

function maskAndInspect(name, urlStr) {
    if (!urlStr) {
        console.log(`\n[${name}] ❌ Tanımlı değil (.env dosyasında bu satır eksik veya boş).`);
        return null;
    }
    try {
        const u = new URL(urlStr);
        console.log(`\n[${name}] Ayrıştırılan bilgiler:`);
        console.log('  Kullanıcı adı :', u.username);
        console.log('  Şifre uzunluğu:', decodeURIComponent(u.password || '').length, 'karakter');
        console.log('  Host          :', u.hostname);
        console.log('  Port          :', u.port);
        console.log('  Veritabanı    :', u.pathname.replace('/', ''));
        // Placeholder unutulmuş mu kontrolü:
        if (urlStr.includes('[YOUR-PASSWORD]') || urlStr.includes('GERCEK_SIFRENIZ') || urlStr.includes('xxxxxxxxxxxx')) {
            console.log('  ⚠️  UYARI: Bağlantı string\'inde hâlâ bir PLACEHOLDER metni var — şifre veya proje referansı değiştirilmemiş görünüyor!');
        }
        return urlStr;
    } catch (err) {
        console.log(`[${name}] ❌ Bağlantı string'i hiç geçerli bir URL değil:`, err.message);
        return null;
    }
}

async function testConnection(name, urlStr) {
    const valid = maskAndInspect(name, urlStr);
    if (!valid) return;

    const pool = new Pool({
        connectionString: valid,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 8000
    });

    try {
        const res = await pool.query('SELECT current_user, now()');
        console.log(`  ✅ [${name}] Bağlantı BAŞARILI! Sunucudaki gerçek kullanıcı: ${res.rows[0].current_user}`);
    } catch (err) {
        console.log(`  ❌ [${name}] Bağlantı BAŞARISIZ: [${err.code || '?'}] ${err.message}`);
    } finally {
        await pool.end();
    }
}

(async () => {
    await testConnection('DATABASE_URL (pooler, 6543)', process.env.DATABASE_URL);
    await testConnection('DIRECT_URL (direct, 5432)', process.env.DIRECT_URL);
})();
