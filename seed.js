require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const REQUIRED_DB_VARS = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME'];
const missing = REQUIRED_DB_VARS.filter(v => !process.env[v]);
if (missing.length > 0) {
    console.error(`❌ Eksik ortam değişkenleri: ${missing.join(', ')}. .env dosyanızı kontrol edin.`);
    process.exit(1);
}

// GÜVENLİK KİLİDİ: Bu script "DELETE FROM users" çalıştırır ve TÜM kullanıcıları siler.
// Gerçek/canlı üniversite veritabanına yanlışlıkla karşı çalıştırılmasını önlemek için
// bilinçli bir onay bayrağı zorunlu kılınmıştır.
if (process.env.ALLOW_SEED !== 'evet-eminim') {
    console.error('❌ Güvenlik kilidi: Bu script TÜM kullanıcıları siler ve yeniden oluşturur.');
    console.error('   Sadece BOŞ bir test/geliştirme veritabanında çalıştırılmalıdır.');
    console.error('   Devam etmek için .env dosyanıza ALLOW_SEED=evet-eminim ekleyin, ardından KALDIRIN.');
    process.exit(1);
}

function generateStrongPassword() {
    // 12 karakterlik, okunabilir (karışıklık yaratan 0/O, 1/l gibi karakterler hariç) rastgele şifre
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let pass = '';
    const bytes = crypto.randomBytes(12);
    for (let i = 0; i < 12; i++) pass += chars[bytes[i] % chars.length];
    return pass;
}

async function seedDatabase() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT || 3306,
        ssl: process.env.DB_SSL === 'true'
            ? { minVersion: 'TLSv1.2', ca: process.env.DB_CA || undefined, rejectUnauthorized: true }
            : undefined
    });

    console.log('🌱 Test verileri yükleniyor...');

    // Her kullanıcı için AYRI ve RASTGELE şifre üret (sabit "1234" yerine)
    const users = [
        { id: 1, name: 'Sistem Yöneticisi', email: 'admin@test.com', role: 'admin' },
        { id: 10, name: 'Prof. Dr. Bölüm Başkanı', email: 'akademik@test.com', role: 'academic' },
        { id: 2, name: 'Uzm. Erg. Ayşe Yılmaz', email: 'super@test.com', role: 'supervisor' }
    ];

    await db.execute('DELETE FROM users');

    const generatedPasswords = [];

    for (const u of users) {
        const plainPassword = generateStrongPassword();
        const hashedPassword = await bcrypt.hash(plainPassword, 10);
        await db.execute(
            'INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
            [u.id, u.name, u.email, hashedPassword, u.role]
        );
        generatedPasswords.push({ ...u, plainPassword });
    }

    // 4. Öğrenci (Süpervizörü: 2)
    const studentPassword = generateStrongPassword();
    const studentHash = await bcrypt.hash(studentPassword, 10);
    await db.execute(
        'INSERT INTO users (id, name, student_no, password_hash, role, supervisor_id) VALUES (?, ?, ?, ?, ?, ?)',
        [3, 'Ali Can', '220000', studentHash, 'student', 2]
    );
    generatedPasswords.push({ id: 3, name: 'Ali Can', student_no: '220000', role: 'student', plainPassword: studentPassword });

    console.log('✅ Test kullanıcıları başarıyla MySQL veritabanına işlendi!');
    console.log('');
    console.log('⚠️  Aşağıdaki şifreleri şimdi kaydedin — bir daha GÖSTERİLMEYECEK:');
    console.table(generatedPasswords.map(u => ({
        Rol: u.role,
        Giriş: u.email || u.student_no,
        Şifre: u.plainPassword
    })));

    await db.end();
}

seedDatabase().catch(console.error);
