require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function seedDatabase() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST || '127.0.0.1',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASS || '',
        database: process.env.DB_NAME || 'ergo_staj'
    });

    console.log('🌱 Test verileri yükleniyor...');

    // Şifreyi BCrypt ile hash'le
    const hashedPassword = await bcrypt.hash('1234', 10);

    // Tabloyu temizle ve varsayılan kullanıcıları ekle
    await db.execute('DELETE FROM users');

    // 1. Admin
    await db.execute(
        'INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [1, 'Sistem Yöneticisi', 'admin@test.com', hashedPassword, 'admin']
    );

    // 2. Akademisyen
    await db.execute(
        'INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [10, 'Prof. Dr. Bölüm Başkanı', 'akademik@test.com', hashedPassword, 'academic']
    );

    // 3. Süpervizör
    await db.execute(
        'INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [2, 'Uzm. Erg. Ayşe Yılmaz', 'super@test.com', hashedPassword, 'supervisor']
    );

    // 4. Öğrenci (Süpervizörü: 2)
    await db.execute(
        'INSERT INTO users (id, name, student_no, password_hash, role, supervisor_id) VALUES (?, ?, ?, ?, ?, ?)',
        [3, 'Ali Can', '220000', hashedPassword, 'student', 2]
    );

    console.log('✅ Test kullanıcıları (Şifre: 1234) başarıyla MySQL veritabanına işlendi!');
    await db.end();
}

seedDatabase().catch(console.error);