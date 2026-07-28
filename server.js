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

// MySQL Bağlantı Havuzu
const db = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'ergo_staj',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- AUDIT LOG YARDIMCI FONKSİYONU ---
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
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Erişim engellendi, token eksik.' });

    jwt.verify(token, process.env.JWT_SECRET || 'super_secret_key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Geçersiz veya süresi dolmuş token.' });
        req.user = user;
        next();
    });
};

const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role) && req.user.role !== 'webmaster') {
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
            query = 'SELECT * FROM users WHERE email = ? AND role IN ("admin", "coordinator", "academic", "supervisor")';
        } else {
            query = 'SELECT * FROM users WHERE student_no = ? AND role = "student"';
        }

        const [rows] = await db.execute(query, [queryParam]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Kullanıcı bulunamadı veya hatalı bilgi.' });
        }

        const user = rows[0];

        let isMatch = false;
        if (user.password_hash && (user.password_hash.startsWith('$2a$') || user.password_hash.startsWith('$2b$') || user.password_hash.startsWith('$2y$'))) {
            isMatch = await bcrypt.compare(password, user.password_hash);
        } else {
            isMatch = (password === user.password_hash);
        }

        if (!isMatch) {
            return res.status(401).json({ message: 'Hatalı şifre.' });
        }

        const token = jwt.sign(
            { id: user.id, name: user.name, role: user.role },
            process.env.JWT_SECRET || 'super_secret_key',
            { expiresIn: '8h' }
        );

        delete user.password_hash;

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

// 2. SÜPERVİZÖRE ATANAN ÖĞRENCİLER VE HEDEF/ONAYLANAN GÜN SAYILARI
app.get('/api/supervisors/:id/students', authenticateToken, async (req, res) => {
    try {
        const supervisorId = req.params.id;
        const [students] = await db.execute(`
            SELECT 
                u.id, 
                u.name, 
                u.student_no, 
                g.total_score,
                i.course_code,
                i.course_name,
                i.start_date,
                i.end_date,
                COALESCE(i.required_days, 20) as required_days,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.status = 'approved') as approved_days,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.status = 'pending') as pending_days
            FROM users u
            LEFT JOIN grades g ON u.id = g.student_id
            LEFT JOIN internships i ON u.id = i.student_id
            WHERE (u.supervisor_id = ? OR i.supervisor_id = ?) AND u.role = 'student'
            ORDER BY u.name ASC
        `, [supervisorId, supervisorId]);

        res.json(students);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Öğrenci listesi çekilemedi.' });
    }
});

// 3. SÜPERVİZÖRÜN ÖĞRENCİLERİNE AİT YOKLAMALAR
app.get('/api/supervisors/:id/attendances', authenticateToken, async (req, res) => {
    try {
        const [attendances] = await db.execute(`
            SELECT a.*, u.name as student_name, u.student_no 
            FROM attendances a
            JOIN users u ON a.student_id = u.id
            WHERE u.supervisor_id = ? OR a.student_id IN (SELECT student_id FROM internships WHERE supervisor_id = ?)
            ORDER BY a.id DESC
        `, [req.params.id, req.params.id]);

        res.json(attendances);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Yoklama listesi çekilemedi.' });
    }
});

// 4. YOKLAMA ONAY / RED GÜNCELLEME
app.put('/api/attendances/:id/status', authenticateToken, authorizeRoles('supervisor', 'coordinator', 'admin'), async (req, res) => {
    const { status } = req.body;
    const attendanceId = req.params.id;

    try {
        await db.execute('UPDATE attendances SET status = ? WHERE id = ?', [status, attendanceId]);
        res.json({ message: 'Yoklama durumu güncellendi.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Yoklama durumu güncellenemedi.' });
    }
});

// 5. TÜM BEKLEYEN YOKLAMALARI TOPLU ONAYLAMA
app.post('/api/supervisors/:id/approve-all', authenticateToken, authorizeRoles('supervisor', 'admin'), async (req, res) => {
    try {
        await db.execute(`
            UPDATE attendances a
            JOIN users u ON a.student_id = u.id
            SET a.status = 'approved'
            WHERE (u.supervisor_id = ? OR a.student_id IN (SELECT student_id FROM internships WHERE supervisor_id = ?)) 
            AND a.status = 'pending'
        `, [req.params.id, req.params.id]);

        res.json({ message: 'Tüm bekleyen yoklamalar onaylandı.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Toplu onay işlemi başarısız.' });
    }
});

// 6. GÜNLÜK YOKLAMA BİLDİRİMİ (Öğrenci Check-in)
app.post('/api/attendance/check-in', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    const studentId = req.user.id;
    const { locationInfo } = req.body;
    
    const now = new Date();
    const dateStr = now.toLocaleDateString('tr-TR');
    const timeStr = now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });

    try {
        const [existing] = await db.execute(
            'SELECT id FROM attendances WHERE student_id = ? AND date = ?', 
            [studentId, dateStr]
        );

        if (existing.length > 0) {
            return res.status(400).json({ message: 'Bugün için zaten yoklama kaydınız bulunmaktadır.' });
        }

        await db.execute(
            'INSERT INTO attendances (student_id, date, time, location_info, status, is_retroactive) VALUES (?, ?, ?, ?, "pending", 0)',
            [studentId, dateStr, timeStr, locationInfo || 'GPS Konumu Alındı']
        );

        await createAuditLog(studentId, 'ATTENDANCE_CHECKIN', studentId, null, { date: dateStr, time: timeStr }, req.ip);

        res.json({ message: 'Yoklama kaydınız başarıyla alındı.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Yoklama kaydedilemedi.' });
    }
});

// 7. MAZERETLİ / GERİYE DÖNÜK YOKLAMA TALEBİ
app.post('/api/attendance/retroactive', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    const studentId = req.user.id;
    const { date, excuse } = req.body;

    try {
        await db.execute(
            'INSERT INTO attendances (student_id, date, time, excuse, status, is_retroactive) VALUES (?, ?, "Mazeretli", ?, "pending", 1)',
            [studentId, date, excuse]
        );

        await createAuditLog(studentId, 'RETROACTIVE_ATTENDANCE_REQUEST', studentId, null, { date, excuse }, req.ip);

        res.json({ message: 'Mazeretli yoklama talebiniz başarıyla iletildi.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Mazeretli yoklama talebi kaydedilemedi.' });
    }
});

// 8. ÖĞRENCİ PANELİ VERİLERİ (Hedef Gün Sayısı & İlerleme Dahil)
app.get('/api/student/data', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    try {
        const studentId = req.user.id;

        const [studentRows] = await db.execute(`
            SELECT u.id, u.name, u.student_no, 
                   s.name as supervisor_name,
                   i.course_code, i.course_name, i.start_date, i.end_date,
                   COALESCE(i.required_days, 20) as required_days
            FROM users u
            LEFT JOIN users s ON u.supervisor_id = s.id
            LEFT JOIN internships i ON u.id = i.student_id
            WHERE u.id = ?
        `, [studentId]);

        const [attendances] = await db.execute(`
            SELECT * FROM attendances WHERE student_id = ? ORDER BY id DESC
        `, [studentId]);

        const studentData = studentRows[0] || {};
        studentData.attendances = attendances;
        studentData.approved_days = attendances.filter(a => a.status === 'approved').length;

        res.json(studentData);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Öğrenci verileri çekilemedi.' });
    }
});

// 9. STAJ KOORDİNATÖRÜ: BÖLÜM ÖĞRENCİLERİ
app.get('/api/coordinator/students', authenticateToken, authorizeRoles('coordinator', 'academic', 'admin'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT 
                u.id, 
                u.name, 
                u.student_no, 
                u.supervisor_id,
                u.department_approved,
                sup.name as supervisor_name,
                i.course_code,
                COALESCE(i.required_days, 20) as required_days,
                g.total_score,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.status = 'approved') as approved_attendance_count,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.is_retroactive = 1) as retroactive_count
            FROM users u
            LEFT JOIN users sup ON u.supervisor_id = sup.id
            LEFT JOIN internships i ON u.id = i.student_id
            LEFT JOIN grades g ON u.id = g.student_id
            WHERE u.role = 'student'
            ORDER BY u.name ASC
        `);

        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Bölüm verileri çekilemedi.' });
    }
});

// 10. STAJ KOORDİNATÖRÜ: AUDIT LOGLARI
app.get('/api/coordinator/attendances/:studentId', authenticateToken, authorizeRoles('coordinator', 'academic', 'admin'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT * FROM attendances WHERE student_id = ? ORDER BY id DESC
        `, [req.params.studentId]);

        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Yoklama kayıtları çekilemedi.' });
    }
});

// 11. STAJ KOORDİNATÖRÜ: BÖLÜM FİNAL ONAYI
app.post('/api/coordinator/approve-student', authenticateToken, authorizeRoles('coordinator', 'academic', 'admin'), async (req, res) => {
    const { studentId } = req.body;

    try {
        await db.execute('UPDATE users SET department_approved = 1 WHERE id = ?', [studentId]);
        await createAuditLog(req.user.id, 'DEPARTMENT_FINAL_APPROVAL', studentId, null, { approved: true }, req.ip);
        res.json({ message: 'Öğrencinin stajı resmi olarak onaylandı.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Onay işlemi kaydedilemedi.' });
    }
});

// 12. ADMIN: ÖĞRENCİ VE HEDEF GÜN SAYISI KAYDI (MySQL Live)
app.post('/api/admin/students/save', authenticateToken, authorizeRoles('admin', 'webmaster'), async (req, res) => {
    const { students } = req.body;

    if (!Array.isArray(students) || students.length === 0) {
        return res.status(400).json({ message: 'Geçerli öğrenci verisi bulunamadı.' });
    }

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        for (const stu of students) {
            let [existing] = await connection.execute('SELECT id FROM users WHERE student_no = ?', [stu.studentNo]);
            let studentId;

            if (existing.length > 0) {
                studentId = existing[0].id;
                await connection.execute(
                    'UPDATE users SET name = ?, supervisor_id = ? WHERE id = ?',
                    [stu.name, stu.supervisorId || null, studentId]
                );
            } else {
                const defaultHash = await bcrypt.hash(stu.password || '1234', 10);
                const [insertRes] = await connection.execute(
                    'INSERT INTO users (name, student_no, password_hash, role, supervisor_id) VALUES (?, ?, ?, "student", ?)',
                    [stu.name, stu.studentNo, defaultHash, stu.supervisorId || null]
                );
                studentId = insertRes.insertId;
            }

            if (stu.courseCode) {
                const requiredDays = stu.requiredDays ? parseInt(stu.requiredDays) : 20;

                await connection.execute(
                    `INSERT INTO internships (student_id, course_code, course_name, start_date, end_date, required_days, supervisor_id) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE 
                        course_code = VALUES(course_code),
                        course_name = VALUES(course_name),
                        start_date = VALUES(start_date),
                        end_date = VALUES(end_date),
                        required_days = VALUES(required_days),
                        supervisor_id = VALUES(supervisor_id)`,
                    [
                        studentId, 
                        stu.courseCode, 
                        stu.courseName || 'Mesleki Uygulama', 
                        stu.startDate || '2026-09-01', 
                        stu.endDate || '2026-10-01', 
                        requiredDays,
                        stu.supervisorId || null
                    ]
                );
            }
        }

        await connection.commit();
        res.json({ message: 'Öğrenciler ve staj tanımları başarıyla eklendi.' });
    } catch (err) {
        await connection.rollback();
        console.error('Kayıt Hatası:', err);
        res.status(500).json({ message: 'Kayıt sırasında hata oluştu.' });
    } finally {
        connection.release();
    }
});

// 13. NOT GİRİŞİ / DÜZENLEME
app.post('/api/grades/assign', authenticateToken, authorizeRoles('supervisor', 'coordinator', 'academic', 'admin'), async (req, res) => {
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

// 14. ÖĞRENCİ DETAYLI NOTU GETİRME
app.get('/api/grades/student/:studentId', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT g.*, u.name as student_name, u.student_no, ev.name as evaluator_name
            FROM grades g
            JOIN users u ON g.student_id = u.id
            LEFT JOIN users ev ON g.evaluator_id = ev.id
            WHERE g.student_id = ?
        `, [req.params.studentId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Henüz not girilmemiş.' });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Not bilgisi çekilemedi.' });
    }
});

// SUNUCUYU BAŞLAT
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Güvenli Backend Sunucusu ${PORT} portunda başarıyla çalışıyor.`);
});