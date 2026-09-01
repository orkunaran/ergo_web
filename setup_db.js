require('dotenv').config();
const mysql = require('mysql2/promise');

async function setupDatabase() {
    try {
        console.log('Canlı MySQL sunucusuna bağlanılıyor...');

        const connection = await mysql.createConnection({
            host: process.env.DB_HOST || '127.0.0.1',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASS || '',
            database: process.env.DB_NAME || 'ergo_staj',
            port: 3306
        });

        console.log('✅ Canlı MySQL Sunucusuna başarıyla bağlandı!');

        // 1. Users Tablosu
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NULL,
                student_no VARCHAR(50) UNIQUE NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('admin', 'coordinator', 'academic', 'supervisor', 'student', 'webmaster') NOT NULL,
                supervisor_id INT NULL,
                department_approved TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (supervisor_id) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);

        // 2. Internships (Staj Tanımları) Tablosu
        await connection.query(`
            CREATE TABLE IF NOT EXISTS internships (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL UNIQUE,
                course_code VARCHAR(50) NOT NULL,
                course_name VARCHAR(255) NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                required_days INT DEFAULT 20,
                supervisor_id INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (supervisor_id) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);

        // 3. Attendances Tablosu
        await connection.query(`
            CREATE TABLE IF NOT EXISTS attendances (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL,
                date VARCHAR(50) NOT NULL,
                time VARCHAR(50) NULL,
                location_info VARCHAR(255) DEFAULT 'GPS Konumu Alındı',
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                is_retroactive TINYINT(1) DEFAULT 0,
                excuse TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);

        // 4. Grades Tablosu
        await connection.query(`
            CREATE TABLE IF NOT EXISTS grades (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT UNIQUE NOT NULL,
                evaluator_id INT NOT NULL,
                total_score INT NOT NULL,
                rubric_details JSON NULL,
                note TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (evaluator_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);

        // 5. Audit Logs Tablosu
        await connection.query(`
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                action VARCHAR(100) NOT NULL,
                target_student_id INT NULL,
                old_value JSON NULL,
                new_value JSON NULL,
                ip_address VARCHAR(45) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);

        console.log('🎉 Tüm tablolar (users, internships, attendances, grades, audit_logs) eksiksiz oluşturuldu!');
        await connection.end();
        process.exit(0);

    } catch (error) {
        console.error('❌ Canlı Veritabanı Kurulum Hatası:', error);
        process.exit(1);
    }
}

setupDatabase();