require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function seedDatabase() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME
    });

    // Test şifresi: "1234" (Bcrypt ile 10 tur hash'leniyor)
    const hashedPassword = await bcrypt.hash('1234', 10);

    const users = [
        ['Prof. Dr. Bölüm Başkanı', 'akademik@test.com', null, hashedPassword, 'academic', null],
        ['Uzm. Erg. Ayşe Yılmaz', 'super@test.com', null, hashedPassword, 'supervisor', null],
        ['Ali Can', null, '220000', hashedPassword, 'student', 2] // 2 id'li süpervizöre atandı
    ];

    for (let u of users) {
        await db.execute(
            'INSERT INTO users (name, email, student_no, password_hash, role, supervisor_id) VALUES (?, ?, ?, ?, ?, ?)',
            u
        );
    }

    console.log('Test kullanıcıları hashlenmiş şifrelerle veritabanına eklendi!');
    process.exit();
}

seedDatabase();