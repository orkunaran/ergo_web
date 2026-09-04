require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

if (!process.env.DATABASE_URL) {
    console.error('❌ Eksik ortam değişkeni: DATABASE_URL. .env dosyanızı kontrol edin.');
    process.exit(1);
}

// GÜVENLİK KİLİDİ: Bu script "DELETE FROM users" çalıştırır ve TÜM kullanıcıları siler.
// Gerçek/canlı Supabase veritabanına yanlışlıkla karşı çalıştırılmasını önlemek için
// bilinçli bir onay bayrağı zorunlu kılınmıştır.
if (process.env.ALLOW_SEED !== 'evet-eminim') {
    console.error('❌ Güvenlik kilidi: Bu script TÜM kullanıcıları siler ve yeniden oluşturur.');
    console.error('   Sadece BOŞ bir test/geliştirme veritabanında çalıştırılmalıdır.');
    console.error('   Devam etmek için .env dosyanıza ALLOW_SEED=evet-eminim ekleyin, ardından KALDIRIN.');
    process.exit(1);
}

function generateStrongPassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let pass = '';
    const bytes = crypto.randomBytes(12);
    for (let i = 0; i < 12; i++) pass += chars[bytes[i] % chars.length];
    return pass;
}

async function seedDatabase() {
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.DATABASE_SSL_STRICT === 'true'
            ? { rejectUnauthorized: true, ca: process.env.DATABASE_CA || undefined }
            : { rejectUnauthorized: false }
    });

    console.log('🌱 Test verileri yükleniyor...');

    const users = [
        { name: 'Sistem Yöneticisi', email: 'admin@test.com', role: 'admin' },
        { name: 'Prof. Dr. Bölüm Başkanı', email: 'akademik@test.com', role: 'academic' },
        { name: 'Uzm. Erg. Ayşe Yılmaz', email: 'super@test.com', role: 'supervisor' }
    ];

    await pool.query('DELETE FROM users');

    const generatedPasswords = [];
    let supervisorId = null;

    for (const u of users) {
        const plainPassword = generateStrongPassword();
        const hashedPassword = await bcrypt.hash(plainPassword, 10);
        const result = await pool.query(
            'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
            [u.name, u.email, hashedPassword, u.role]
        );
        if (u.role === 'supervisor') supervisorId = result.rows[0].id;
        generatedPasswords.push({ ...u, plainPassword });
    }

    // Öğrenci (süpervizörü: yukarıda oluşturulan süpervizör)
    const studentPassword = generateStrongPassword();
    const studentHash = await bcrypt.hash(studentPassword, 10);
    await pool.query(
        'INSERT INTO users (name, student_no, password_hash, role, supervisor_id) VALUES ($1, $2, $3, $4, $5)',
        ['Ali Can', '220000', studentHash, 'student', supervisorId]
    );
    generatedPasswords.push({ name: 'Ali Can', student_no: '220000', role: 'student', plainPassword: studentPassword });

    console.log('✅ Test kullanıcıları başarıyla Supabase veritabanına işlendi!');
    console.log('');
    console.log('⚠️  Aşağıdaki şifreleri şimdi kaydedin — bir daha GÖSTERİLMEYECEK:');
    console.table(generatedPasswords.map(u => ({
        Rol: u.role,
        Giriş: u.email || u.student_no,
        Şifre: u.plainPassword
    })));

    await pool.end();
}

seedDatabase().catch((err) => {
    console.error(err);
    process.exit(1);
});
