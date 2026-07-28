require('dotenv').config();
const mysql = require('mysql2/promise');

async function setupDatabase() {
    try {
        console.log('Canlı MySQL sunucusuna bağlanılıyor...');

        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASS,
            database: process.env.DB_NAME,
            port: 3306
        });

        console.log('✅ Canlı MySQL Sunucusuna başarıyla bağlandı!');

        // Tabloları Oluştur
        const createUsersTable = `
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NULL,
                student_no VARCHAR(50) UNIQUE NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('admin', 'academic', 'supervisor', 'student') NOT NULL,
                supervisor_id INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (supervisor_id) REFERENCES users(id) ON DELETE SET NULL
            );
        `;

        const createAttendancesTable = `
            CREATE TABLE IF NOT EXISTS attendances (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL,
                date DATE NOT NULL,
                time TIME NOT NULL,
                location_info VARCHAR(255) DEFAULT 'GPS Konumu Alındı',
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                is_retroactive BOOLEAN DEFAULT FALSE,
                excuse TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
            );
        `;

        const createGradesTable = `
            CREATE TABLE IF NOT EXISTS grades (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT UNIQUE NOT NULL,
                evaluator_id INT NOT NULL,
                total_score INT NOT NULL,
                rubric_details JSON NULL,
                note TEXT NULL,
                department_approved BOOLEAN DEFAULT FALSE,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (evaluator_id) REFERENCES users(id)
            );
        `;

        const createAuditLogsTable = `
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                action VARCHAR(100) NOT NULL,
                target_student_id INT NULL,
                old_value TEXT NULL,
                new_value TEXT NULL,
                ip_address VARCHAR(45) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `;

        await connection.query(createUsersTable);
        await connection.query(createAttendancesTable);
        await connection.query(createGradesTable);
        await connection.query(createAuditLogsTable);

        console.log('🎉 Tüm tablolar (users, attendances, grades, audit_logs) canlı veritabanında oluşturuldu!');
        await connection.end();
        process.exit();

    } catch (error) {
        console.error('❌ Canlı Veritabanı Kurulum Hatası:', error);
        process.exit(1);
    }
}

setupDatabase();