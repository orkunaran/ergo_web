require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const db = require('./db');

if (!process.env.JWT_SECRET) {
    console.error('❌ KRİTİK HATA: JWT_SECRET ortam değişkeni tanımlı değil. Sunucu başlatılmıyor.');
    process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();
app.set('trust proxy', 1);

// --- 1. GÜVENLİK HTTP BAŞLIKLARI (Helmet) ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.tailwindcss.com', 'https://cdnjs.cloudflare.com'],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com'],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// --- 2. STATİK DOSYALAR ---
app.use(express.static(__dirname, { index: false }));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(express.json());

const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://ergo-web-pi.vercel.app/')
    .split(',')
    .map(o => o.trim());

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('CORS: Bu origin için erişim izni yok.'));
    },
    credentials: true
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { message: 'Çok fazla giriş denemesi yapıldı. Lütfen 15 dakika sonra tekrar deneyin.' },
    standardHeaders: true,
    legacyHeaders: false
});

// --- 3. AUDIT LOG YARDIMCISI ---
async function createAuditLog(userId, action, targetStudentId, oldValue, newValue, ip) {
    try {
        await db.execute(
            `INSERT INTO audit_logs (user_id, action, target_student_id, old_value, new_value, ip_address) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                userId || null, 
                action, 
                targetStudentId || null, 
                oldValue ? JSON.stringify(oldValue) : null, 
                newValue ? JSON.stringify(newValue) : null, 
                ip || null
            ]
        );
    } catch (err) {
        console.error('Audit Log Hatası:', err.message);
    }
}

// --- 4. GÜVENLİK MIDDLEWARE'LERİ ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Yetkisiz erişim: Giriş belirteci (token) eksik.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Geçersiz veya süresi dolmuş oturum. Lütfen tekrar giriş yapın.' });
        }
        req.user = user;
        next();
    });
};

const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role) && req.user.role !== 'webmaster' && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Bu işlem için yetkiniz bulunmamaktadır.' });
        }
        next();
    };
};

const requireOwnIdOrPrivileged = (req, res, next) => {
    const privilegedRoles = ['admin', 'webmaster', 'coordinator', 'academic'];
    if (privilegedRoles.includes(req.user.role)) {
        return next();
    }
    if (String(req.user.id) !== String(req.params.id)) {
        return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece kendi verilerinize erişebilirsiniz.' });
    }
    next();
};

// --- 5. API ENDPOINT'LERİ ---

// [1] GÜVENLİ GİRİŞ (E-posta VEYA Kullanıcı Adı ile Giriş)
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { identifier, password, loginType } = req.body || {};

    if (!identifier || !password) {
        return res.status(400).json({ message: 'Lütfen kullanıcı adı / e-posta ve şifrenizi girin.' });
    }

    try {
        let query = '';
        let queryParam = identifier.trim();

        if (loginType === 'staff') {
            query = `SELECT * FROM users 
                     WHERE (LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?)) 
                       AND role IN ('admin', 'coordinator', 'academic', 'supervisor')`;
            const [rows] = await db.execute(query, [queryParam, queryParam]);

            if (rows.length === 0) {
                return res.status(401).json({ message: 'Kullanıcı bulunamadı veya hatalı giriş türü seçildi.' });
            }

            const user = rows[0];
            const isBcryptHash = user.password_hash && /^\$2[aby]\$/.test(user.password_hash);
            if (!isBcryptHash) {
                return res.status(500).json({ message: 'Hesap yapılandırma hatası. Lütfen yöneticinizle iletişime geçin.' });
            }

            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (!isMatch) {
                return res.status(401).json({ message: 'Hatalı şifre.' });
            }

            const token = jwt.sign(
                { id: user.id, name: user.name, role: user.role, email: user.email, username: user.username },
                JWT_SECRET,
                { expiresIn: '10h' }
            );

            delete user.password_hash;
            return res.json({ message: 'Giriş başarılı', token, user });

        } else {
            query = `SELECT * FROM users 
                     WHERE (student_no = ? OR LOWER(username) = LOWER(?)) 
                       AND role = 'student'`;
            const [rows] = await db.execute(query, [queryParam, queryParam]);

            if (rows.length === 0) {
                return res.status(401).json({ message: 'Öğrenci bulunamadı.' });
            }

            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (!isMatch) {
                return res.status(401).json({ message: 'Hatalı şifre.' });
            }

            const token = jwt.sign(
                { id: user.id, name: user.name, role: user.role, student_no: user.student_no, username: user.username },
                JWT_SECRET,
                { expiresIn: '10h' }
            );

            delete user.password_hash;
            return res.json({ message: 'Giriş başarılı', token, user });
        }
    } catch (error) {
        console.error('Login Hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: Giriş yapılamadı.' });
    }
});

// [2] SÜPERVİZÖRE ATANAN ÖĞRENCİLER (Bireysel VEYA Departman Ortaklığı)
app.get('/api/supervisors/:id/students', authenticateToken, authorizeRoles('supervisor', 'admin', 'coordinator', 'academic'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = parseInt(req.params.id, 10);
        
        const [students] = await db.execute(`
            SELECT DISTINCT
                u.id, 
                u.name, 
                u.student_no, 
                g.total_score,
                i.course_code,
                i.course_name,
                i.internship_type,
                i.start_date,
                i.end_date,
                COALESCE(i.required_days, 20) as required_days,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.status = 'approved') as approved_days,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.status = 'pending') as pending_days
            FROM users u
            LEFT JOIN grades g ON u.id = g.student_id
            LEFT JOIN internships i ON u.id = i.student_id
            LEFT JOIN department_supervisors ds_m ON i.morning_dept_id = ds_m.department_id
            LEFT JOIN department_supervisors ds_a ON i.afternoon_dept_id = ds_a.department_id
            WHERE u.role = 'student' 
              AND (
                  u.supervisor_id = ? 
                  OR i.supervisor_id = ? 
                  OR ds_m.supervisor_id = ? 
                  OR ds_a.supervisor_id = ?
              )
            ORDER BY u.name ASC
        `, [supervisorId, supervisorId, supervisorId, supervisorId]);

        res.json(students);
    } catch (error) {
        console.error('Süpervizör Öğrenci Hatası:', error);
        res.status(500).json({ message: 'Öğrenci listesi çekilemedi.' });
    }
});

// [3] SÜPERVİZÖRÜN ÖĞRENCİLERİNE AİT YOKLAMALAR
app.get('/api/supervisors/:id/attendances', authenticateToken, authorizeRoles('supervisor', 'admin', 'coordinator', 'academic'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = parseInt(req.params.id, 10);
        const [attendances] = await db.execute(`
            SELECT DISTINCT a.*, u.name as student_name, u.student_no, i.internship_type
            FROM attendances a
            JOIN users u ON a.student_id = u.id
            LEFT JOIN internships i ON u.id = i.student_id
            LEFT JOIN department_supervisors ds_m ON i.morning_dept_id = ds_m.department_id
            LEFT JOIN department_supervisors ds_a ON i.afternoon_dept_id = ds_a.department_id
            WHERE u.supervisor_id = ? 
               OR i.supervisor_id = ?
               OR ds_m.supervisor_id = ? 
               OR ds_a.supervisor_id = ?
            ORDER BY a.id DESC
        `, [supervisorId, supervisorId, supervisorId, supervisorId]);

        res.json(attendances);
    } catch (error) {
        console.error('Yoklama Listesi Hatası:', error);
        res.status(500).json({ message: 'Yoklama listesi çekilemedi.' });
    }
});

// [4] YOKLAMA DURUM GÜNCELLEME (ONAY / RED)
app.put('/api/attendances/:id/status', authenticateToken, authorizeRoles('supervisor', 'coordinator', 'admin'), async (req, res) => {
    const { status } = req.body || {};
    const attendanceId = req.params.id;

    try {
        const [oldRows] = await db.execute('SELECT * FROM attendances WHERE id = ?', [attendanceId]);
        if (oldRows.length === 0) {
            return res.status(404).json({ message: 'Yoklama kaydı bulunamadı.' });
        }

        await db.execute('UPDATE attendances SET status = ? WHERE id = ?', [status, attendanceId]);
        
        await createAuditLog(
            req.user.id, 
            'ATTENDANCE_STATUS_CHANGE', 
            oldRows[0].student_id, 
            { status: oldRows[0].status }, 
            { status }, 
            req.ip
        );

        res.json({ message: 'Yoklama durumu başarıyla güncellendi.' });
    } catch (error) {
        console.error('Yoklama Güncelleme Hatası:', error);
        res.status(500).json({ message: 'Yoklama durumu güncellenemedi.' });
    }
});

// [5] TÜM BEKLEYEN YOKLAMALARI TOPLU ONAYLAMA (PostgreSQL Uyumlu)
app.post('/api/supervisors/:id/approve-all', authenticateToken, authorizeRoles('supervisor', 'admin'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = parseInt(req.params.id, 10);
        await db.execute(`
            UPDATE attendances
            SET status = 'approved'
            WHERE student_id IN (
                SELECT DISTINCT u.id FROM users u
                LEFT JOIN internships i ON u.id = i.student_id
                LEFT JOIN department_supervisors ds_m ON i.morning_dept_id = ds_m.department_id
                LEFT JOIN department_supervisors ds_a ON i.afternoon_dept_id = ds_a.department_id
                WHERE u.supervisor_id = ? 
                   OR i.supervisor_id = ?
                   OR ds_m.supervisor_id = ? 
                   OR ds_a.supervisor_id = ?
            )
            AND status = 'pending'
        `, [supervisorId, supervisorId, supervisorId, supervisorId]);

        await createAuditLog(req.user.id, 'BULK_ATTENDANCE_APPROVE', null, null, { supervisorId }, req.ip);

        res.json({ message: 'Tüm bekleyen yoklamalar onaylandı.' });
    } catch (error) {
        console.error('Toplu Onay Hatası:', error);
        res.status(500).json({ message: 'Toplu onay işlemi başarısız.' });
    }
});

// [6] GÜNLÜK YOKLAMA (Öğrenci Check-in: Çift / Tek Yoklama ve Gün-Saat Kontrolü)
app.post('/api/attendance/check-in', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    const studentId = req.user.id;
    const { locationInfo } = req.body || {};
    
    const now = new Date();
    const dayOfWeek = now.getDay();
    const currentHour = now.getHours();
    const dateStr = now.toISOString().split('T')[0];
    const timeStr = now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });

    try {
        const [internshipRows] = await db.execute('SELECT internship_type FROM internships WHERE student_id = ?', [studentId]);
        const internshipType = internshipRows.length > 0 ? internshipRows[0].internship_type : 'internal';

        let sessionType = 'full_day';

        if (internshipType === 'internal') {
            if (![2, 3, 4, 5].includes(dayOfWeek)) {
                return res.status(400).json({ message: 'Okul içi staj günleri sadece Salı, Çarşamba, Perşembe ve Cuma günleridir.' });
            }

            if (currentHour < 9 || currentHour >= 17) {
                return res.status(400).json({ message: 'Yoklama sadece staj saatleri (09:00 - 17:00) içerisinde alınabilir.' });
            }

            sessionType = currentHour < 13 ? 'morning' : 'afternoon';
        }

        const [existing] = await db.execute(
            'SELECT id FROM attendances WHERE student_id = ? AND date = ? AND session_type = ?', 
            [studentId, dateStr, sessionType]
        );

        if (existing.length > 0) {
            const oturumAdi = sessionType === 'morning' ? 'Sabah' : (sessionType === 'afternoon' ? 'Öğleden Sonra' : 'Günlük');
            return res.status(400).json({ message: `Bugün için ${oturumAdi} yoklama kaydınız zaten alınmıştır.` });
        }

        await db.execute(
            "INSERT INTO attendances (student_id, date, time, location_info, status, is_retroactive, session_type) VALUES (?, ?, ?, ?, 'pending', 0, ?)",
            [studentId, dateStr, timeStr, locationInfo || 'GPS Konumu Alındı', sessionType]
        );

        await createAuditLog(studentId, 'ATTENDANCE_CHECKIN', studentId, null, { date: dateStr, time: timeStr, sessionType }, req.ip);

        res.json({ message: `${sessionType === 'morning' ? 'Sabah' : (sessionType === 'afternoon' ? 'Öğleden Sonra' : '')} yoklamanız başarıyla kaydedildi.` });
    } catch (error) {
        console.error('Check-in Hatası:', error);
        res.status(500).json({ message: 'Yoklama kaydedilemedi.' });
    }
});

// [7] MAZERETLİ / GERİYE DÖNÜK YOKLAMA TALEBİ
app.post('/api/attendance/retroactive', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    const studentId = req.user.id;
    const { date, excuse, sessionType } = req.body || {};

    if (!date || !excuse) {
        return res.status(400).json({ message: 'Tarih ve mazeret açıklaması zorunludur.' });
    }

    try {
        await db.execute(
            "INSERT INTO attendances (student_id, date, time, excuse, status, is_retroactive, session_type) VALUES (?, ?, 'Mazeretli', ?, 'pending', 1, ?)",
            [studentId, date, excuse, sessionType || 'full_day']
        );

        await createAuditLog(studentId, 'RETROACTIVE_ATTENDANCE_REQUEST', studentId, null, { date, excuse, sessionType }, req.ip);

        res.json({ message: 'Mazeretli yoklama talebiniz başarıyla iletildi.' });
    } catch (error) {
        console.error('Mazeret Talebi Hatası:', error);
        res.status(500).json({ message: 'Mazeretli yoklama talebi kaydedilemedi.' });
    }
});

// [8] ÖĞRENCİ PANELİ VERİLERİ
app.get('/api/student/data', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    try {
        const studentId = req.user.id;

        const [studentRows] = await db.execute(`
            SELECT u.id, u.name, u.student_no, 
                   s.name as supervisor_name,
                   adv.name as advisor_name,
                   i.course_code, i.course_name, i.internship_type, i.start_date, i.end_date,
                   COALESCE(i.required_days, 20) as required_days,
                   dept_m.name as morning_dept_name,
                   dept_a.name as afternoon_dept_name
            FROM users u
            LEFT JOIN users s ON u.supervisor_id = s.id
            LEFT JOIN users adv ON u.advisor_id = adv.id
            LEFT JOIN internships i ON u.id = i.student_id
            LEFT JOIN departments dept_m ON i.morning_dept_id = dept_m.id
            LEFT JOIN departments dept_a ON i.afternoon_dept_id = dept_a.id
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
        console.error('Öğrenci Veri Hatası:', error);
        res.status(500).json({ message: 'Öğrenci verileri çekilemedi.' });
    }
});

// [9] STAJ KOORDİNATÖRÜ & AKADEMİK DANIŞMAN: ÖĞRENCİ LİSTESİ
app.get('/api/coordinator/students', authenticateToken, authorizeRoles('coordinator', 'academic', 'admin'), async (req, res) => {
    try {
        const userId = req.user.id;
        const userRole = req.user.role;

        let filterSql = '';
        let params = [];
        if (userRole === 'academic') {
            filterSql = 'AND (u.advisor_id = ? OR u.supervisor_id = ?)';
            params = [userId, userId];
        }

        const [rows] = await db.execute(`
            SELECT 
                u.id, 
                u.name, 
                u.student_no, 
                u.supervisor_id,
                u.advisor_id,
                u.department_approved,
                sup.name as supervisor_name,
                adv.name as advisor_name,
                i.course_code,
                i.internship_type,
                COALESCE(i.required_days, 20) as required_days,
                g.total_score,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.status = 'approved') as approved_attendance_count,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.is_retroactive = 1) as retroactive_count
            FROM users u
            LEFT JOIN users sup ON u.supervisor_id = sup.id
            LEFT JOIN users adv ON u.advisor_id = adv.id
            LEFT JOIN internships i ON u.id = i.student_id
            LEFT JOIN grades g ON u.id = g.student_id
            WHERE u.role = 'student' ${filterSql}
            ORDER BY u.name ASC
        `, params);

        res.json(rows);
    } catch (error) {
        console.error('Koordinatör Öğrenci Listesi Hatası:', error);
        res.status(500).json({ message: 'Bölüm verileri çekilemedi.' });
    }
});

// [10] STAJ KOORDİNATÖRÜ / DANIŞMAN: ÖĞRENCİ YOKLAMA DETAYI
app.get('/api/coordinator/attendances/:studentId', authenticateToken, authorizeRoles('coordinator', 'academic', 'admin'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT * FROM attendances WHERE student_id = ? ORDER BY id DESC
        `, [req.params.studentId]);

        res.json(rows);
    } catch (error) {
        console.error('Yoklama Çekme Hatası:', error);
        res.status(500).json({ message: 'Yoklama kayıtları çekilemedi.' });
    }
});

// [11] STAJ KOORDİNATÖRÜ: BÖLÜM FİNAL ONAYI
app.post('/api/coordinator/approve-student', authenticateToken, authorizeRoles('coordinator', 'admin'), async (req, res) => {
    const { studentId } = req.body || {};

    try {
        await db.execute('UPDATE users SET department_approved = 1 WHERE id = ?', [studentId]);
        await createAuditLog(req.user.id, 'DEPARTMENT_FINAL_APPROVAL', studentId, null, { approved: true }, req.ip);
        res.json({ message: 'Öğrencinin stajı resmi olarak onaylandı.' });
    } catch (error) {
        console.error('Koordinatör Onay Hatası:', error);
        res.status(500).json({ message: 'Onay işlemi kaydedilemedi.' });
    }
});

// [12] ADMIN: ÖĞRENCİ, DANIŞMAN VE STAJ KAYDI / GÜNCELLEMESİ (UPSERT)
app.post('/api/admin/students/save', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { students } = req.body || {};

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
                if (stu.password && stu.password.trim() !== '') {
                    const newHash = await bcrypt.hash(stu.password.trim(), 10);
                    await connection.execute(
                        'UPDATE users SET name = ?, supervisor_id = ?, advisor_id = ?, password_hash = ? WHERE id = ?',
                        [stu.name, stu.supervisorId || null, stu.advisorId || null, newHash, studentId]
                    );
                } else {
                    await connection.execute(
                        'UPDATE users SET name = ?, supervisor_id = ?, advisor_id = ? WHERE id = ?',
                        [stu.name, stu.supervisorId || null, stu.advisorId || null, studentId]
                    );
                }
            } else {
                const defaultHash = await bcrypt.hash(stu.password || '1234', 10);
                const [insertRes] = await connection.execute(
                    "INSERT INTO users (name, student_no, password_hash, role, supervisor_id, advisor_id) VALUES (?, ?, ?, 'student', ?, ?) RETURNING id",
                    [stu.name, stu.studentNo, defaultHash, stu.supervisorId || null, stu.advisorId || null]
                );
                studentId = insertRes[0].id;
            }

            if (stu.courseCode) {
                const requiredDays = stu.requiredDays ? parseInt(stu.requiredDays, 10) : 20;

                await connection.execute(
                    `INSERT INTO internships (
                        student_id, course_code, course_name, internship_type, 
                        start_date, end_date, required_days, supervisor_id, morning_dept_id, afternoon_dept_id
                     ) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT (student_id) DO UPDATE SET 
                        course_code = EXCLUDED.course_code,
                        course_name = EXCLUDED.course_name,
                        internship_type = EXCLUDED.internship_type,
                        start_date = EXCLUDED.start_date,
                        end_date = EXCLUDED.end_date,
                        required_days = EXCLUDED.required_days,
                        supervisor_id = EXCLUDED.supervisor_id,
                        morning_dept_id = EXCLUDED.morning_dept_id,
                        afternoon_dept_id = EXCLUDED.afternoon_dept_id`,
                    [
                        studentId, 
                        stu.courseCode, 
                        stu.courseName || 'Mesleki Uygulama', 
                        stu.internshipType || 'external',
                        stu.startDate || '2026-09-01', 
                        stu.endDate || '2026-10-01', 
                        requiredDays,
                        stu.supervisorId || null,
                        stu.morningDeptId || null,
                        stu.afternoonDeptId || null
                    ]
                );
            }
        }

        await connection.commit();
        res.json({ message: 'Öğrenciler ve staj tanımları başarıyla kaydedildi/güncellendi.' });
    } catch (err) {
        await connection.rollback();
        console.error('Öğrenci Kayıt Hatası:', err);
        res.status(500).json({ message: 'Öğrenci kaydı sırasında veritabanı hatası oluştu.' });
    } finally {
        connection.release();
    }
});

// [13] ADMIN: SÜPERVİZÖR / PERSONEL KAYDI VE GÜNCELLEMESİ (Username Desteğiyle)
app.post('/api/admin/supervisors/save', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { name, email, username, password, role } = req.body || {};

    if (!name || !email) {
        return res.status(400).json({ message: 'İsim ve E-posta alanları zorunludur.' });
    }

    const cleanUsername = username ? username.trim().toLowerCase() : null;
    const requesterIsAdmin = req.user.role === 'admin' || req.user.role === 'webmaster';
    const requestedRole = role || 'supervisor';

    const PRIVILEGED_ROLES = ['admin', 'webmaster', 'coordinator', 'academic'];
    if (!requesterIsAdmin && PRIVILEGED_ROLES.includes(requestedRole)) {
        await createAuditLog(req.user.id, 'UNAUTHORIZED_ROLE_ESCALATION_ATTEMPT', null, null, { attemptedRole: requestedRole, targetEmail: email }, req.ip);
        return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece yönetici üst yetki tanımlayabilir.' });
    }
    const assignedRole = requesterIsAdmin ? requestedRole : 'supervisor';

    try {
        const [existing] = await db.execute('SELECT id, role FROM users WHERE email = ?', [email]);

        if (existing.length > 0) {
            if (password && password.trim() !== '') {
                const newHash = await bcrypt.hash(password.trim(), 10);
                await db.execute(
                    'UPDATE users SET name = ?, username = ?, role = ?, password_hash = ? WHERE id = ?',
                    [name, cleanUsername, assignedRole, newHash, existing[0].id]
                );
            } else {
                await db.execute(
                    'UPDATE users SET name = ?, username = ?, role = ? WHERE id = ?',
                    [name, cleanUsername, assignedRole, existing[0].id]
                );
            }
            res.json({ message: 'Personel bilgileri başarıyla güncellendi.' });
        } else {
            const defaultHash = await bcrypt.hash(password || '1234', 10);
            await db.execute(
                'INSERT INTO users (name, email, username, password_hash, role) VALUES (?, ?, ?, ?, ?)',
                [name, email, cleanUsername, defaultHash, assignedRole]
            );
            res.json({ message: 'Yeni personel başarıyla sisteme eklendi.' });
        }
    } catch (err) {
        console.error('Personel Kayıt Hatası:', err);
        if (err.message && err.message.includes('users_username_key')) {
            return res.status(400).json({ message: 'Bu kullanıcı adı zaten başka bir personel tarafından kullanılıyor.' });
        }
        res.status(500).json({ message: 'Personel kaydı sırasında hata oluştu.' });
    }
});

// [14] ADMIN: SÜPERVİZÖR VE DANIŞMAN LİSTESİ (Username Kolonuyla)
app.get('/api/admin/supervisors', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT id, name, email, username, role, created_at 
            FROM users 
            WHERE role IN ('supervisor', 'coordinator', 'academic') 
            ORDER BY name ASC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Süpervizör Listeleme Hatası:', error);
        res.status(500).json({ message: 'Personel listesi çekilemedi.' });
    }
});

// [14.1] TÜM DEPARTMANLARI LİSTELE (Bağlı Hocalarla Birlikte)
app.get('/api/admin/departments', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    try {
        const [depts] = await db.execute('SELECT * FROM departments ORDER BY id ASC');
        const [assignments] = await db.execute(`
            SELECT ds.department_id, u.id as user_id, u.name as user_name, u.email 
            FROM department_supervisors ds
            JOIN users u ON ds.supervisor_id = u.id
            ORDER BY u.name ASC
        `);

        const result = depts.map(d => ({
            ...d,
            supervisors: assignments.filter(a => a.department_id === d.id)
        }));

        res.json(result);
    } catch (error) {
        console.error('Departman listeleme hatası:', error);
        res.status(500).json({ message: 'Departmanlar çekilemedi.' });
    }
});

// [14.2] DEPARTMANA HOCA / ASİSTAN ATA
app.post('/api/admin/departments/assign', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { departmentId, supervisorId } = req.body || {};
    if (!departmentId || !supervisorId) {
        return res.status(400).json({ message: 'Departman ve hoca seçimi zorunludur.' });
    }

    try {
        await db.execute(
            `INSERT INTO department_supervisors (department_id, supervisor_id) 
             VALUES (?, ?) 
             ON CONFLICT (department_id, supervisor_id) DO NOTHING`,
            [departmentId, supervisorId]
        );
        res.json({ message: 'Hoca departmana başarıyla atandı.' });
    } catch (error) {
        console.error('Departman hoca atama hatası:', error);
        res.status(500).json({ message: 'Atama işlemi başarısız.' });
    }
});

// [14.3] DEPARTMANDAN HOCA ÇIKAR
app.delete('/api/admin/departments/remove', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { departmentId, supervisorId } = req.body || {};
    try {
        await db.execute(
            'DELETE FROM department_supervisors WHERE department_id = ? AND supervisor_id = ?',
            [departmentId, supervisorId]
        );
        res.json({ message: 'Hoca departmandan çıkarıldı.' });
    } catch (error) {
        console.error('Departmandan hoca çıkarma hatası:', error);
        res.status(500).json({ message: 'İşlem başarısız.' });
    }
});

// [15] NOT GİRİŞİ / DÜZENLEME (Departman Ortaklığı Koruması)
app.post('/api/grades/assign', authenticateToken, authorizeRoles('supervisor', 'coordinator', 'academic', 'admin'), async (req, res) => {
    const evaluatorId = req.user.id;
    const { studentId, totalScore, rubricDetails, note } = req.body || {};

    try {
        if (req.user.role === 'supervisor' || req.user.role === 'academic') {
            const [permCheck] = await db.execute(`
                SELECT u.id FROM users u
                LEFT JOIN internships i ON u.id = i.student_id
                LEFT JOIN department_supervisors ds_m ON i.morning_dept_id = ds_m.department_id
                LEFT JOIN department_supervisors ds_a ON i.afternoon_dept_id = ds_a.department_id
                WHERE u.id = ? AND (
                    u.supervisor_id = ? 
                    OR i.supervisor_id = ? 
                    OR ds_m.supervisor_id = ? 
                    OR ds_a.supervisor_id = ?
                )
            `, [studentId, evaluatorId, evaluatorId, evaluatorId, evaluatorId]);

            if (permCheck.length === 0) {
                await createAuditLog(evaluatorId, 'UNAUTHORIZED_GRADE_ATTEMPT', studentId, null, { attemptedScore: totalScore }, req.ip);
                return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Bu öğrencinin bağlı olduğu departmanda veya stajda değerlendirme yetkiniz bulunmamaktadır!' });
            }
        }

        const [oldGradeRows] = await db.execute('SELECT * FROM grades WHERE student_id = ?', [studentId]);
        const oldGrade = oldGradeRows[0] || null;

        const cleanRubric = typeof rubricDetails === 'object' ? rubricDetails : {};

        if (oldGrade) {
            await db.execute(
                `UPDATE grades SET evaluator_id = ?, total_score = ?, rubric_details = ?, note = ? 
                 WHERE student_id = ?`,
                [evaluatorId, totalScore, cleanRubric, note, studentId]
            );
        } else {
            await db.execute(
                `INSERT INTO grades (student_id, evaluator_id, total_score, rubric_details, note) 
                 VALUES (?, ?, ?, ?, ?)`,
                [studentId, evaluatorId, totalScore, cleanRubric, note]
            );
        }

        await createAuditLog(
            evaluatorId, 
            oldGrade ? 'GRADE_UPDATE' : 'GRADE_CREATE', 
            studentId, 
            oldGrade, 
            { totalScore, rubricDetails: cleanRubric, note }, 
            req.ip
        );

        res.json({ message: 'Staj değerlendirme notu başarıyla kaydedildi.' });
    } catch (error) {
        console.error('Not Kayıt Hatası:', error);
        res.status(500).json({ message: 'Not kaydı sırasında sunucu hatası oluştu.' });
    }
});

// [16] ÖĞRENCİ DETAYLI NOTUNU GETİRME
app.get('/api/grades/student/:studentId', authenticateToken, async (req, res) => {
    try {
        const studentId = req.params.studentId;
        const currentUserId = req.user.id;
        const currentUserRole = req.user.role;

        if (currentUserRole === 'student' && String(currentUserId) !== String(studentId)) {
            return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece kendi notunuzu görüntüleyebilirsiniz.' });
        }

        if (currentUserRole === 'supervisor' || currentUserRole === 'academic') {
            const [ownership] = await db.execute(`
                SELECT u.id FROM users u
                LEFT JOIN internships i ON u.id = i.student_id
                LEFT JOIN department_supervisors ds_m ON i.morning_dept_id = ds_m.department_id
                LEFT JOIN department_supervisors ds_a ON i.afternoon_dept_id = ds_a.department_id
                WHERE u.id = ? AND (
                    u.supervisor_id = ? 
                    OR u.advisor_id = ?
                    OR i.supervisor_id = ? 
                    OR ds_m.supervisor_id = ? 
                    OR ds_a.supervisor_id = ?
                )
            `, [studentId, currentUserId, currentUserId, currentUserId, currentUserId, currentUserId]);

            if (ownership.length === 0) {
                return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Bu öğrencinin notunu görme yetkiniz bulunmamaktadır.' });
            }
        }

        const [rows] = await db.execute(`
            SELECT g.*, u.name as student_name, u.student_no, ev.name as evaluator_name
            FROM grades g
            JOIN users u ON g.student_id = u.id
            LEFT JOIN users ev ON g.evaluator_id = ev.id
            WHERE g.student_id = ?
        `, [studentId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Henüz not girilmemiş.' });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error('Not Getirme Hatası:', error);
        res.status(500).json({ message: 'Not bilgisi çekilemedi.' });
    }
});

// --- 6. GENEL HATA YAKALAYICI ---
app.use((err, req, res, next) => {
    console.error('Yakalanmamış Hata:', err.message);
    if (res.headersSent) {
        return next(err);
    }
    res.status(err.status || 500).json({ message: 'Sunucu hatası oluştu. Lütfen tekrar deneyin.' });
});

module.exports = app;