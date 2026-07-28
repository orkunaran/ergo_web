require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Güvenlik & CORS Ayarları
app.use(express.json());
app.use(cors({
    origin: '*', // Canlıya geçildiğinde 'https://ergostaj.hacettepe.edu.tr' yazılacak
    credentials: true
}));

// MySQL Bağlantı Havuzu (Connection Pool)
const db = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'ergo_staj',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- AUDIT LOG (DENETİM İZİ) YARDIMCI FONKSİYONU ---
async function createAuditLog(userId, action, targetStudentId, oldValue, newValue, ip) {
    try {
        await db.execute(
            `INSERT INTO audit_logs (user_id, action, target_student_id, old_value, new_value, ip_address) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [userId, action, targetStudentId, JSON.stringify(oldValue), JSON.stringify(newValue), ip || null]
        );
    } catch (err) {
        console.error('Audit Log Kaydedilemedi:', err);
    }
}

// --- GÜVENLİK MIDDLEWARE'LERİ ---

// 1. JWT Doğrulama (Kimlik Kontrolü)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

    if (!token) return res.status(401).json({ message: 'Erişim engellendi, token eksik.' });

    jwt.verify(token, process.env.JWT_SECRET || 'super_secret_key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Geçersiz veya süresi dolmuş token.' });
        req.user = user;
        next();
    });
};

// 2. Rol Bazlı Yetkilendirme (Authorization)
const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Bu işlem için yetkiniz bulunmamaktadır.' });
        }
        next();
    };
};

// --- API ENDPOINT'LERİ ---

// 1. GÜVENLİ GİRİŞ (LOGIN)
app.post('/api/auth/login', async (req, res) => {
    const { identifier, password, loginType } = req.body; 

    try {
        let query = '';
        let queryParam = identifier;

        if (loginType === 'staff') {
            query = 'SELECT * FROM users WHERE email = ? AND role IN ("admin", "academic", "supervisor")';
        } else {
            query = 'SELECT * FROM users WHERE student_no = ? AND role = "student"';
        }

        const [rows] = await db.execute(query, [queryParam]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Kullanıcı bulunamadı veya hatalı bilgi.' });
        }

        const user = rows[0];

        // Şifre Doğrulama (BCrypt hash kontrolü ve düz metin geriye dönük uyumluluğu)
        let isMatch = false;
        if (user.password_hash && (user.password_hash.startsWith('$2a$') || user.password_hash.startsWith('$2b$') || user.password_hash.startsWith('$2y$'))) {
            isMatch = await bcrypt.compare(password, user.password_hash);
        } else {
            isMatch = (password === user.password_hash); // Düz metin şifreler için fallback
        }

        if (!isMatch) {
            return res.status(401).json({ message: 'Hatalı şifre.' });
        }

        // JWT Token Üretme
        const token = jwt.sign(
            { id: user.id, name: user.name, role: user.role },
            process.env.JWT_SECRET || 'super_secret_key',
            { expiresIn: '8h' }
        );

        delete user.password_hash; // Hassas veriyi yanıttan temizle

        res.json({
            message: 'Giriş başarılı',
            token,
            user
        });

    } catch (error) {
        console.error('Login Hata Logu:', error);
        res.status(500).json({ message: 'Sunucu hatası oluştu.' });
    }
});


// 2. SÜPERVİZÖRE ATANAN ÖĞRENCİLERİ GETİRME
app.get('/api/supervisors/:id/students', async (req, res) => {
    try {
        const [students] = await db.execute(`
            SELECT u.id, u.name, u.student_no, g.total_score,
            (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id) as attendance_count
            FROM users u
            LEFT JOIN grades g ON u.id = g.student_id
            WHERE u.supervisor_id = ? AND u.role = 'student'
        `, [req.params.id]);

        res.json(students);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Öğrenci listesi çekilemedi.' });
    }
});

// 3. SÜPERVİZÖRÜN ÖĞRENCİLERİNE AİT YOKLAMALARI GETİRME
app.get('/api/supervisors/:id/attendances', async (req, res) => {
    try {
        const [attendances] = await db.execute(`
            SELECT a.*, u.name as student_name, u.student_no 
            FROM attendances a
            JOIN users u ON a.student_id = u.id
            WHERE u.supervisor_id = ?
            ORDER BY a.id DESC
        `, [req.params.id]);

        res.json(attendances);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Yoklama listesi çekilemedi.' });
    }
});

// 4. YOKLAMA VERME (Öğrenci)
app.post('/api/attendance/check-in', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    const studentId = req.user.id;
    const { locationInfo } = req.body;
    
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0];
    const timeStr = now.toTimeString().split(' ')[0];

    try {
        const [existing] = await db.execute(
            'SELECT id FROM attendances WHERE student_id = ? AND date = ?', 
            [studentId, dateStr]
        );

        if (existing.length > 0) {
            return res.status(400).json({ message: 'Bugün için zaten yoklama kaydınız bulunmaktadır.' });
        }

        await db.execute(
            'INSERT INTO attendances (student_id, date, time, location_info, status) VALUES (?, ?, ?, ?, "pending")',
            [studentId, dateStr, timeStr, locationInfo || 'GPS Konumu Alındı']
        );

        await createAuditLog(studentId, 'ATTENDANCE_CHECKIN', studentId, null, { date: dateStr, time: timeStr }, req.ip);

        res.json({ message: 'Yoklama kaydınız başarıyla alındı.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Yoklama kaydedilemedi.' });
    }
});

// 5. NOT GİRİŞİ / DÜZENLEME (IDOR Korumalı)
app.post('/api/grades/assign', authenticateToken, authorizeRoles('supervisor', 'academic', 'admin'), async (req, res) => {
    const evaluatorId = req.user.id;
    const { studentId, totalScore, rubricDetails, note } = req.body;

    try {
        if (req.user.role === 'supervisor') {
            const [studentCheck] = await db.execute(
                'SELECT id FROM users WHERE id = ? AND supervisor_id = ?',
                [studentId, evaluatorId]
            );

            if (studentCheck.length === 0) {
                await createAuditLog(evaluatorId, 'UNAUTHORIZED_GRADE_ATTEMPT', studentId, null, { attemptedScore: totalScore }, req.ip);
                return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Size atanmamış bir öğrenciye not veremezsiniz!' });
            }
        }

        const [oldGradeRows] = await db.execute('SELECT * FROM grades WHERE student_id = ?', [studentId]);
        const oldGrade = oldGradeRows[0] || null;

        if (oldGrade) {
            await db.execute(
                `UPDATE grades SET evaluator_id = ?, total_score = ?, rubric_details = ?, note = ? 
                 WHERE student_id = ?`,
                [evaluatorId, totalScore, JSON.stringify(rubricDetails), note, studentId]
            );
        } else {
            await db.execute(
                `INSERT INTO grades (student_id, evaluator_id, total_score, rubric_details, note) 
                 VALUES (?, ?, ?, ?, ?)`,
                [studentId, evaluatorId, totalScore, JSON.stringify(rubricDetails), note]
            );
        }

        await createAuditLog(
            evaluatorId, 
            oldGrade ? 'GRADE_UPDATE' : 'GRADE_CREATE', 
            studentId, 
            oldGrade, 
            { totalScore, rubricDetails, note }, 
            req.ip
        );

        res.json({ message: 'Not başarıyla kaydedildi.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Not kaydı sırasında sunucu hatası oluştu.' });
    }
});

// SUNUCUYU BAŞLAT
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Güvenli Backend Sunucusu ${PORT} portunda başarıyla çalışıyor.`);
});