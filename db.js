require('dotenv').config();
const { Pool } = require('pg');

// Vercel veya Supabase hangi ismi verdiyse otomatik yakalar
const connectionString = 
    process.env.DATABASE_URL || 
    process.env.POSTGRES_URL || 
    process.env.POSTGRES_PRISMA_URL;

if (!connectionString) {
    console.error('❌ KRİTİK HATA: DATABASE_URL veya POSTGRES_URL bulunamadı!');
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: {
        rejectUnauthorized: false // Supabase SSL için şarttır
    }
});

module.exports = {
    query: (text, params) => pool.query(text, params),
    execute: async (text, params) => {
        // MySQL stili ? işaretlerini PostgreSQL $1, $2 formatına çevirir
        let paramIndex = 1;
        const pgText = text.replace(/\?/g, () => `$${paramIndex++}`);
        const res = await pool.query(pgText, params);
        return [res.rows, res.fields];
    },
    getConnection: async () => {
        const client = await pool.connect();
        return {
            execute: async (text, params) => {
                let paramIndex = 1;
                const pgText = text.replace(/\?/g, () => `$${paramIndex++}`);
                const res = await client.query(pgText, params);
                return [res.rows, res.fields];
            },
            beginTransaction: () => client.query('BEGIN'),
            commit: () => client.query('COMMIT'),
            rollback: () => client.query('ROLLBACK'),
            release: () => client.release()
        };
    }
};