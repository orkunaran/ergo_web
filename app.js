require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const db = require('./db'); // Postgres (Supabase) bağlantı katmanı

// --- 0. ZORUNLU ORTAM DEĞİŞKENİ KONTROLÜ ---
// JWT_SECRET tanımlı değilse, bilinen bir varsayılan değerle sunucu ASLA çalışmamalı.
// Aksi halde token'lar herkes tarafından sahte olarak üretilebilir.
if (!process.env.JWT_SECRET) {
    console.error('❌ KRİTİK HATA: JWT_SECRET ortam değişkeni tanımlı değil. Sunucu başlatılmıyor.');
    process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
// (DATABASE_URL kontrolü db.js içinde yapılıyor — burada require('./db') satırı zaten
// eksikse sunucuyu başlatmadan önce sürecin çökmesini sağlıyor.)

const app = express();

// Vercel/Proxy arkasında doğru IP tespiti için (rate limiter ve audit log IP'leri için önemli)
app.set('trust proxy', 1);

// --- 1. GÜVENLİK HTTP BAŞLIKLARI (Helmet) ---
// Sadece bu uygulamanın gerçekten kullandığı CDN'lere izin veren sıkı bir CSP.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // Tailwind CDN script'i tarayıcıda çalışan bir derleyici (JIT) olduğu için
            // 'unsafe-eval' gerektiriyor; bu olmadan Tailwind sessizce çalışmayı durdurup
            // sayfa tamamen stilsiz görünür.
            // Bu proje, sayfa mantığını (login, veri çekme vb.) her HTML dosyasının
            // içine gömülü <script> bloğu olarak yazıyor (nonce/hash tabanlı bir
            // şablon sistemi yok). Bu yüzden 'unsafe-inline' burada ZORUNLU — aksi
            // halde tarayıcı bu script'lerin tamamını (giriş formu dahil) çalıştırmayı
            // reddediyor. Bu, CSP'nin XSS'e karşı sağladığı korumayı zayıflatır;
            // birincil XSS savunması artık kullanıcı verisinin HTML'e basılmadan önce
            // escape edilmesidir (bkz. escapeHtml() kullanımları). İleride daha sıkı
            // bir CSP isterseniz, script'leri harici .js dosyalarına taşıyıp
            // sunucu tarafında üretilen bir nonce ile CSP'yi sıkılaştırabiliriz.
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.tailwindcss.com'],
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
// Yerel geliştirmede Express bu HTML dosyalarını proje kökünden sunar.
// Vercel'e deploy edildiğinde bu dosyalar zaten statik varlık olarak otomatik sunulur
// (aşağıdaki satırlar sadece "vercel dev" / yerel "node server.js" için devrededir).
app.use(express.static(__dirname, { index: false }));

// Ana sayfa yönlendirmesi
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// JSON ve CORS Yapılandırması
app.use(express.json());

// İzin verilen originler (virgülle ayrılmış olarak .env'den okunur, yoksa aşağıdaki varsayılan kullanılır)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://ergostaj.hacettepe.edu.tr')
    .split(',')
    .map(o => o.trim());

app.use(cors({
    origin: function (origin, callback) {
        // origin yoksa (Postman/sunucu-içi istek gibi) izin ver; aksi halde listede olmalı
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('CORS: Bu origin için erişim izni yok.'));
    },
    credentials: true
}));

// Login endpoint'ine özel brute-force koruması
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 10, // aynı IP'den 15 dakikada en fazla 10 deneme
    message: { message: 'Çok fazla giriş denemesi yapıldı. Lütfen 15 dakika sonra tekrar deneyin.' },
    standardHeaders: true,
    legacyHeaders: false
});

// --- 3. VERİTABANI ---
// Bağlantı havuzu artık db.js içinde (Postgres/Supabase). Yukarıda require('./db') ile alındı.

// --- 3. AUDIT LOG (DENETİM İZİ) YARDIMCISI ---
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

// Bir :id route parametresinin, işlemi yapan kullanıcının kendisine ait olmasını zorunlu kılar.
// admin/webmaster/coordinator/academic rolleri bu kısıtlamadan muaftır (tüm süpervizörlere erişebilirler).
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

// [1] GÜVENLİ GİRİŞ (LOGIN)
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { identifier, password, loginType } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ message: 'Lütfen kullanıcı adı / e-posta ve şifrenizi girin.' });
    }

    try {
        let query = '';
        let queryParam = identifier.trim();

        if (loginType === 'staff') {
            query = "SELECT * FROM users WHERE email = ? AND role IN ('admin', 'coordinator', 'academic', 'supervisor')";
        } else {
            query = "SELECT * FROM users WHERE student_no = ? AND role = 'student'";
        }

        const [rows] = await db.execute(query, [queryParam]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Kullanıcı bulunamadı veya hatalı giriş türü seçildi.' });
        }

        const user = rows[0];

        // Şifre doğrulaması: sadece bcrypt hash'i kabul edilir (düz metin karşılaştırma kaldırıldı)
        const isBcryptHash = user.password_hash && /^\$2[aby]\$/.test(user.password_hash);
        if (!isBcryptHash) {
            console.error(`Güvenlik uyarısı: kullanıcı ${user.id} için bcrypt olmayan şifre kaydı tespit edildi.`);
            return res.status(500).json({ message: 'Hesap yapılandırma hatası. Lütfen yöneticinizle iletişime geçin.' });
        }
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ message: 'Hatalı şifre.' });
        }

        const token = jwt.sign(
            { id: user.id, name: user.name, role: user.role, email: user.email },
            JWT_SECRET,
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
        res.status(500).json({ message: 'Sunucu hatası: Giriş yapılamadı.' });
    }
});

// [2] SÜPERVİZÖRE ATANAN ÖĞRENCİLER
app.get('/api/supervisors/:id/students', authenticateToken, authorizeRoles('supervisor', 'admin', 'coordinator', 'academic'), requireOwnIdOrPrivileged, async (req, res) => {
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
        console.error('Süpervizör Öğrenci Hatası:', error);
        res.status(500).json({ message: 'Öğrenci listesi çekilemedi.' });
    }
});

// [3] SÜPERVİZÖRÜN ÖĞRENCİLERİNE AİT YOKLAMALAR
app.get('/api/supervisors/:id/attendances', authenticateToken, authorizeRoles('supervisor', 'admin', 'coordinator', 'academic'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = req.params.id;
        const [attendances] = await db.execute(`
            SELECT a.*, u.name as student_name, u.student_no 
            FROM attendances a
            JOIN users u ON a.student_id = u.id
            WHERE u.supervisor_id = ? OR a.student_id IN (SELECT student_id FROM internships WHERE supervisor_id = ?)
            ORDER BY a.id DESC
        `, [supervisorId, supervisorId]);

        res.json(attendances);
    } catch (error) {
        console.error('Yoklama Listesi Hatası:', error);
        res.status(500).json({ message: 'Yoklama listesi çekilemedi.' });
    }
});

// [4] YOKLAMA DURUM GÜNCELLEME (ONAY / RED)
app.put('/api/attendances/:id/status', authenticateToken, authorizeRoles('supervisor', 'coordinator', 'admin'), async (req, res) => {
    const { status } = req.body;
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

// [5] TÜM BEKLEYEN YOKLAMALARI TOPLU ONAYLAMA
app.post('/api/supervisors/:id/approve-all', authenticateToken, authorizeRoles('supervisor', 'admin'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = req.params.id;
        await db.execute(`
            UPDATE attendances a
            SET status = 'approved'
            FROM users u
            WHERE a.student_id = u.id
              AND (u.supervisor_id = ? OR a.student_id IN (SELECT student_id FROM internships WHERE supervisor_id = ?))
              AND a.status = 'pending'
        `, [supervisorId, supervisorId]);

        await createAuditLog(req.user.id, 'BULK_ATTENDANCE_APPROVE', null, null, { supervisorId }, req.ip);

        res.json({ message: 'Tüm bekleyen yoklamalar onaylandı.' });
    } catch (error) {
        console.error('Toplu Onay Hatası:', error);
        res.status(500).json({ message: 'Toplu onay işlemi başarısız.' });
    }
});

// [6] GÜNLÜK YOKLAMA (Öğrenci Check-in)
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
            "INSERT INTO attendances (student_id, date, time, location_info, status, is_retroactive) VALUES (?, ?, ?, ?, 'pending', 0)",
            [studentId, dateStr, timeStr, locationInfo || 'GPS Konumu Alındı']
        );

        await createAuditLog(studentId, 'ATTENDANCE_CHECKIN', studentId, null, { date: dateStr, time: timeStr }, req.ip);

        res.json({ message: 'Yoklama kaydınız başarıyla alındı.' });
    } catch (error) {
        console.error('Check-in Hatası:', error);
        res.status(500).json({ message: 'Yoklama kaydedilemedi.' });
    }
});

// [7] MAZERETLİ / GERİYE DÖNÜK YOKLAMA TALEBİ
app.post('/api/attendance/retroactive', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    const studentId = req.user.id;
    const { date, excuse } = req.body;

    if (!date || !excuse) {
        return res.status(400).json({ message: 'Tarih ve mazeret açıklaması zorunludur.' });
    }

    try {
        await db.execute(
            "INSERT INTO attendances (student_id, date, time, excuse, status, is_retroactive) VALUES (?, ?, 'Mazeretli', ?, 'pending', 1)",
            [studentId, date, excuse]
        );

        await createAuditLog(studentId, 'RETROACTIVE_ATTENDANCE_REQUEST', studentId, null, { date, excuse }, req.ip);

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
        console.error('Öğrenci Veri Hatası:', error);
        res.status(500).json({ message: 'Öğrenci verileri çekilemedi.' });
    }
});

// [9] STAJ KOORDİNATÖRÜ: TÜM BÖLÜM ÖĞRENCİLERİ
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
        console.error('Koordinatör Öğrenci Listesi Hatası:', error);
        res.status(500).json({ message: 'Bölüm verileri çekilemedi.' });
    }
});

// [10] STAJ KOORDİNATÖRÜ: ÖĞRENCİ YOKLAMA DETAYI
app.get('/api/coordinator/attendances/:studentId', authenticateToken, authorizeRoles('coordinator', 'academic', 'admin'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT * FROM attendances WHERE student_id = ? ORDER BY id DESC
        `, [req.params.studentId]);

        res.json(rows);
    } catch (error) {
        console.error('Koordinatör Yoklama Çekme Hatası:', error);
        res.status(500).json({ message: 'Yoklama kayıtları çekilemedi.' });
    }
});

// [11] STAJ KOORDİNATÖRÜ: BÖLÜM FİNAL ONAYI
app.post('/api/coordinator/approve-student', authenticateToken, authorizeRoles('coordinator', 'academic', 'admin'), async (req, res) => {
    const { studentId } = req.body;

    try {
        await db.execute('UPDATE users SET department_approved = 1 WHERE id = ?', [studentId]);
        await createAuditLog(req.user.id, 'DEPARTMENT_FINAL_APPROVAL', studentId, null, { approved: true }, req.ip);
        res.json({ message: 'Öğrencinin stajı resmi olarak onaylandı.' });
    } catch (error) {
        console.error('Koordinatör Onay Hatası:', error);
        res.status(500).json({ message: 'Onay işlemi kaydedilemedi.' });
    }
});

// [12] ADMIN: ÖĞRENCİ VE STAJ KAYDI / GÜNCELLEMESİ (UPSERT - Toplu & Tekli)
app.post('/api/admin/students/save', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
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
                    "INSERT INTO users (name, student_no, password_hash, role, supervisor_id) VALUES (?, ?, ?, 'student', ?) RETURNING id",
                    [stu.name, stu.studentNo, defaultHash, stu.supervisorId || null]
                );
                studentId = insertRes[0].id;
            }

            if (stu.courseCode) {
                const requiredDays = stu.requiredDays ? parseInt(stu.requiredDays) : 20;

                await connection.execute(
                    `INSERT INTO internships (student_id, course_code, course_name, start_date, end_date, required_days, supervisor_id) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT (student_id) DO UPDATE SET 
                        course_code = EXCLUDED.course_code,
                        course_name = EXCLUDED.course_name,
                        start_date = EXCLUDED.start_date,
                        end_date = EXCLUDED.end_date,
                        required_days = EXCLUDED.required_days,
                        supervisor_id = EXCLUDED.supervisor_id`,
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
        res.json({ message: 'Öğrenciler ve staj tanımları başarıyla kaydedildi/güncellendi.' });
    } catch (err) {
        await connection.rollback();
        console.error('Öğrenci Kayıt Hatası:', err);
        res.status(500).json({ message: 'Öğrenci kaydı sırasında veritabanı hatası oluştu.' });
    } finally {
        connection.release();
    }
});

// [13] ADMIN: SÜPERVİZÖR / PERSONEL KAYDI VE GÜNCELLEMESİ (UPSERT)
app.post('/api/admin/supervisors/save', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email) {
        return res.status(400).json({ message: 'İsim ve E-posta alanları zorunludur.' });
    }

    const requesterIsAdmin = req.user.role === 'admin' || req.user.role === 'webmaster';
    const requestedRole = role || 'supervisor';

    // GÜVENLİK: Koordinatör, kendini veya başkasını admin/webmaster/coordinator yapamaz
    // (yetki yükseltme saldırısına karşı). Koordinatör sadece "supervisor" rolü atayabilir.
    const PRIVILEGED_ROLES = ['admin', 'webmaster', 'coordinator', 'academic'];
    if (!requesterIsAdmin && PRIVILEGED_ROLES.includes(requestedRole)) {
        await createAuditLog(req.user.id, 'UNAUTHORIZED_ROLE_ESCALATION_ATTEMPT', null, null, { attemptedRole: requestedRole, targetEmail: email }, req.ip);
        return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece yönetici (admin) yönetici/koordinatör yetkisi atayabilir.' });
    }
    const assignedRole = requesterIsAdmin ? requestedRole : 'supervisor';

    try {
        const [existing] = await db.execute('SELECT id, role FROM users WHERE email = ?', [email]);

        // GÜVENLİK: Koordinatör, mevcut bir admin/webmaster/coordinator hesabını düzenleyemez.
        if (existing.length > 0 && !requesterIsAdmin && PRIVILEGED_ROLES.includes(existing[0].role)) {
            await createAuditLog(req.user.id, 'UNAUTHORIZED_PRIVILEGED_ACCOUNT_EDIT_ATTEMPT', existing[0].id, null, { targetEmail: email }, req.ip);
            return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Bu hesabı düzenleme yetkiniz yok.' });
        }

        if (existing.length > 0) {
            // Mevcut süpervizörü güncelle
            await db.execute(
                'UPDATE users SET name = ?, role = ? WHERE id = ?',
                [name, assignedRole, existing[0].id]
            );
            res.json({ message: 'Süpervizör bilgileri başarıyla güncellendi.' });
        } else {
            // Yeni süpervizör oluştur
            const defaultHash = await bcrypt.hash(password || '1234', 10);
            await db.execute(
                'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [name, email, defaultHash, assignedRole]
            );
            res.json({ message: 'Yeni süpervizör başarıyla sisteme eklendi.' });
        }
    } catch (err) {
        console.error('Süpervizör Kayıt Hatası:', err);
        res.status(500).json({ message: 'Süpervizör kaydı sırasında hata oluştu.' });
    }
});

// [14] ADMIN: SÜPERVİZÖR LİSTESİ GETİRME (Dropdown ve tablolar için)
app.get('/api/admin/supervisors', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT id, name, email, role, created_at 
            FROM users 
            WHERE role IN ('supervisor', 'coordinator', 'academic') 
            ORDER BY name ASC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Süpervizör Listeleme Hatası:', error);
        res.status(500).json({ message: 'Süpervizör listesi çekilemedi.' });
    }
});

// [15] NOT GİRİŞİ / DÜZENLEME (Rubrik)
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
        console.error('Not Kayıt Hatası:', error);
        res.status(500).json({ message: 'Not kaydı sırasında sunucu hatası oluştu.' });
    }
});

// [16] ÖĞRENCİ DETAYLI NOTUNU GETİRME
app.get('/api/grades/student/:studentId', authenticateToken, async (req, res) => {
    try {
        // Öğrenci sadece kendi notunu görebilir; süpervizör sadece kendi öğrencisininkini görebilir
        if (req.user.role === 'student' && String(req.user.id) !== String(req.params.studentId)) {
            return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece kendi notunuzu görüntüleyebilirsiniz.' });
        }
        if (req.user.role === 'supervisor') {
            const [ownership] = await db.execute(
                'SELECT id FROM users WHERE id = ? AND supervisor_id = ?',
                [req.params.studentId, req.user.id]
            );
            if (ownership.length === 0) {
                return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Size atanmamış bir öğrencinin notunu göremezsiniz.' });
            }
        }

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
        console.error('Not Getirme Hatası:', error);
        res.status(500).json({ message: 'Not bilgisi çekilemedi.' });
    }
});

// --- 6. GENEL HATA YAKALAYICI ---
// Route içindeki try/catch'lerin dışında kalan her hata (ör. CORS reddi, beklenmeyen
// middleware hataları) buraya düşer. Express'in varsayılan davranışı bir HTML hata
// sayfası (ve stack trace) döndürmektir — bu hem frontend'in JSON beklerken hata
// almasına hem de sunucu iç detaylarının sızmasına yol açar. Bunun yerine her zaman
// sade bir JSON hatası dönüyoruz.
app.use((err, req, res, next) => {
    console.error('Yakalanmamış Hata:', err.message);
    if (res.headersSent) {
        return next(err);
    }
    res.status(err.status || 500).json({ message: 'Sunucu hatası oluştu. Lütfen tekrar deneyin.' });
});

// --- 7. UYGULAMAYI DIŞA AKTAR ---
// app.listen() burada YOK: yerel geliştirme için server.js, Vercel için api/index.js kullanır.
module.exports = app;