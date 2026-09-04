// MYSQL -> POSTGRES (Supabase) GEÇİŞ KATMANI
// Bu dosya, app.js'teki mevcut db.execute(sql, params) çağrılarının neredeyse
// hiç değişmeden çalışmasını sağlamak için "?" placeholder'larını Postgres'in
// "$1, $2..." biçimine çevirir ve sonucu mysql2'nin [rows] imzasına benzer
// şekilde döndürür.
require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
    console.error('❌ KRİTİK HATA: DATABASE_URL ortam değişkeni tanımlı değil. Sunucu başlatılmıyor.');
    process.exit(1);
}

// Supabase'in Supavisor connection pooler'ı (transaction mode, port 6543) serverless
// ortamlar için özel olarak tasarlanmıştır. Pooler zaten üst seviyede havuzlama yaptığı
// için buradaki max değeri düşük tutulmalı (Vercel'de fonksiyon başına 1-3 önerilir).
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Supabase pooler'a bağlanırken sertifika zinciri genelde sistem CA'larına
    // bağlı olmadığından varsayılan olarak rejectUnauthorized:false kullanılır
    // (trafik yine de TLS ile şifrelenir). Daha sıkı doğrulama isterseniz
    // DATABASE_SSL_STRICT=true yapıp DATABASE_CA ile Supabase'in sertifikasını sağlayın.
    ssl: process.env.DATABASE_SSL_STRICT === 'true'
        ? { rejectUnauthorized: true, ca: process.env.DATABASE_CA || undefined }
        : { rejectUnauthorized: false },
    max: parseInt(process.env.DB_POOL_MAX || '3', 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
    console.error('Beklenmeyen Postgres havuz hatası:', err.message);
});

// "?" placeholder'larını sırayla "$1, $2, ..." ile değiştirir.
function toPgPlaceholders(sql) {
    let i = 0;
    return sql.replace(/\?/g, () => `$${++i}`);
}

// mysql2'nin `const [rows] = await db.execute(sql, params)` kullanım şekliyle
// uyumlu olacak şekilde sonucu [rows, fields] olarak döner.
async function execute(sql, params = []) {
    const pgSql = toPgPlaceholders(sql);
    const result = await pool.query(pgSql, params);
    return [result.rows, result.fields];
}

// Transaction gereken işlemler için (mysql2'deki getConnection() karşılığı).
async function getConnection() {
    const client = await pool.connect();
    return {
        execute: async (sql, params = []) => {
            const pgSql = toPgPlaceholders(sql);
            const result = await client.query(pgSql, params);
            return [result.rows, result.fields];
        },
        beginTransaction: () => client.query('BEGIN'),
        commit: () => client.query('COMMIT'),
        rollback: () => client.query('ROLLBACK'),
        release: () => client.release()
    };
}

module.exports = { execute, getConnection, pool };
