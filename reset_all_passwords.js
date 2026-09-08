// TEST KOLAYLIĞI SCRIPT'İ — tüm kullanıcıların şifresini "1234" yapar.
// SADECE geliştirme/test aşamasında kullanın. Gerçek öğrenci/personel verisi
// olan bir veritabanında ASLA çalıştırmayın — herkesin şifresini tahmin
// edilebilir hale getirir.
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL tanımlı değil.');
    process.exit(1);
}

if (process.env.ALLOW_RESET !== 'evet-eminim') {
    console.error('❌ Güvenlik kilidi: Bu script TÜM kullanıcıların şifresini "1234" yapar.');
    console.error('   Devam etmek için: ALLOW_RESET=evet-eminim node reset-all-passwords.js');
    process.exit(1);
}

(async () => {
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    const hash = await bcrypt.hash('1234', 10);
    const result = await pool.query('UPDATE users SET password_hash = $1', [hash]);

    console.log(`✅ ${result.rowCount} kullanıcının şifresi "1234" olarak güncellendi.`);
    await pool.end();
})().catch(err => {
    console.error('Hata:', err.message);
    process.exit(1);
});