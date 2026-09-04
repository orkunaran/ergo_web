// SUPABASE (POSTGRESQL) ŞEMA KURULUMU
require('dotenv').config();
const { Pool } = require('pg');

// Şema oluşturma (CREATE TABLE, TRIGGER, RLS vb.) gibi tek seferlik/idari işlemler
// için DIRECT_URL (session/direct bağlantı, port 5432) kullanılır — transaction-mode
// pooler (DATABASE_URL, port 6543) bazı idari komutlarda sınırlı davranabilir.
// DIRECT_URL tanımlı değilse DATABASE_URL'e geri döner (uyarı verir).
const connectionString = process.env.DIRECT_URL || process.env.DATABASE_URL;
if (!connectionString) {
    console.error('❌ KRİTİK HATA: DIRECT_URL veya DATABASE_URL tanımlı değil. .env dosyanızı kontrol edin.');
    process.exit(1);
}
if (!process.env.DIRECT_URL) {
    console.warn('⚠️  DIRECT_URL tanımlı değil, DATABASE_URL (pooler) ile devam ediliyor. Şema kurulumu için DIRECT_URL önerilir.');
}

async function setupDatabase() {
    const pool = new Pool({
        connectionString,
        ssl: process.env.DATABASE_SSL_STRICT === 'true'
            ? { rejectUnauthorized: true, ca: process.env.DATABASE_CA || undefined }
            : { rejectUnauthorized: false }
    });

    try {
        console.log('Supabase (PostgreSQL) sunucusuna bağlanılıyor...');
        const client = await pool.connect();
        console.log('✅ Supabase sunucusuna başarıyla bağlandı!');

        // 1. Users Tablosu
        // Not: MySQL'deki ENUM yerine TEXT + CHECK kullanıyoruz; ileride yeni bir rol
        // eklemek gerekirse (ör. ALTER TABLE ... DROP CONSTRAINT / ADD CONSTRAINT) daha kolay.
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE,
                student_no VARCHAR(50) UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'coordinator', 'academic', 'supervisor', 'student', 'webmaster')),
                supervisor_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
                department_approved SMALLINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        `);

        // 2. Internships (Staj Tanımları) Tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS internships (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                student_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                course_code VARCHAR(50) NOT NULL,
                course_name VARCHAR(255) NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                required_days INTEGER NOT NULL DEFAULT 20,
                supervisor_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        `);

        // 3. Attendances Tablosu
        // date/time bilinçli olarak TEXT tutuluyor (uygulama kodu bunları hazır
        // formatlanmış metin olarak üretip okuyor; DATE/TIME tipine geçmek app.js'te
        // ayrı bir değişiklik gerektirir).
        await client.query(`
            CREATE TABLE IF NOT EXISTS attendances (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                date TEXT NOT NULL,
                time TEXT,
                location_info VARCHAR(255) DEFAULT 'GPS Konumu Alındı',
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
                is_retroactive SMALLINT NOT NULL DEFAULT 0,
                excuse TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        `);

        // 4. Grades Tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS grades (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                student_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                evaluator_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                total_score INTEGER NOT NULL,
                rubric_details JSONB,
                note TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        `);

        // 5. Audit Logs Tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
                action VARCHAR(100) NOT NULL,
                target_student_id INTEGER,
                old_value JSONB,
                new_value JSONB,
                ip_address VARCHAR(45),
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        `);

        // updated_at otomatik güncellensin diye trigger (MySQL'deki
        // "ON UPDATE CURRENT_TIMESTAMP" karşılığı — Postgres'te bunun otomatiği yok).
        await client.query(`
            CREATE OR REPLACE FUNCTION set_updated_at()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = now();
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        `);
        await client.query(`
            DROP TRIGGER IF EXISTS trg_grades_updated_at ON grades;
        `);
        await client.query(`
            CREATE TRIGGER trg_grades_updated_at
            BEFORE UPDATE ON grades
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        `);

        // --- ROW LEVEL SECURITY (Savunma Derinliği) ---
        // Uygulamamız TÜM erişim kontrolünü Express backend'inde (JWT + rol kontrolü)
        // yapıyor ve veritabanına her zaman backend'in "service" bağlantısıyla erişiyor.
        // Yine de RLS'i açıp HİÇBİR politika tanımlamıyoruz: bu sayede biri yanlışlıkla
        // Supabase'in otomatik REST/GraphQL API'sini bu tablolar için etkinleştirirse
        // (anon/authenticated rolleriyle), varsayılan olarak HİÇBİR satır dışarı sızmaz.
        // Backend'in kullandığı bağlantı (postgres kullanıcısı / connection pooler) RLS'i
        // by-pass eder, yani uygulamanın çalışmasını etkilemez.
        const tables = ['users', 'internships', 'attendances', 'grades', 'audit_logs'];
        for (const t of tables) {
            await client.query(`ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;`);
        }

        console.log('🎉 Tüm tablolar (users, internships, attendances, grades, audit_logs) eksiksiz oluşturuldu!');
        console.log('🔒 Row Level Security tüm tablolarda etkinleştirildi (varsayılan: erişim reddedilir).');

        client.release();
        await pool.end();
        process.exit(0);

    } catch (error) {
        console.error('❌ Supabase Veritabanı Kurulum Hatası:', error);
        process.exit(1);
    }
}

setupDatabase();
