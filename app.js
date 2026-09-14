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

// --- KURUMSAL LOGO & PWA İKON SERVİSİ (/icons/icon-192.png ve /icons/icon-512.png) ---
const huIconSvg = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <linearGradient id="huGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#5e2b97" />
      <stop offset="100%" stop-color="#3b1563" />
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="110" fill="url(#huGrad)" />
  <circle cx="256" cy="256" r="215" fill="none" stroke="#ffffff" stroke-width="8" opacity="0.9" />
  <circle cx="256" cy="256" r="195" fill="#411b6b" stroke="#d8b4fe" stroke-width="3" stroke-dasharray="10 6" opacity="0.85" />
  <text x="256" y="210" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="95" font-weight="900" fill="#ffffff" text-anchor="middle">H.Ü.</text>
  <text x="256" y="275" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="32" font-weight="800" fill="#e9d5ff" text-anchor="middle">ERGOTERAPİ</text>
  <text x="256" y="325" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="20" font-weight="700" fill="#c084fc" text-anchor="middle">STAJ PORTALI</text>
  <text x="256" y="380" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="18" font-weight="600" fill="#ffffff" opacity="0.8" text-anchor="middle">★ 1967 ★</text>
</svg>
`;

app.get(['/icons/icon-192.png', '/icons/icon-512.png', '/icons/icon.svg', '/favicon.ico'], (req, res) => {
    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(huIconSvg);
});

// --- 3. YARDIMCI VE SENKRONİZASYON FONKSİYONLARI ---

function slugifyName(name) {
    if (!name) return 'kullanici';
    const clean = String(name)
        .toLowerCase()
        .trim()
        .replace(/^(prof\.|prof|doç\.|doç|dr\.|dr|uzm\.|uzm|fzt\.|fzt|erg\.|erg)\s+/gi, '')
        .replace(/ğ/g, 'g').replace(/ü/g, 'u').replace(/ş/g, 's')
        .replace(/ı/g, 'i').replace(/ö/g, 'o').replace(/ç/g, 'c')
        .replace(/[^a-z0-9\s]/g, '')
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .join('.');
    return clean || 'kullanici';
}

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

// Resmi ve Dini Bayramları Otomatik Çeken Fonksiyon (Nager.Date Açık API)
async function syncPublicHolidays(years = [2026, 2027]) {
    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS public_holidays (
                id SERIAL PRIMARY KEY,
                holiday_date DATE UNIQUE NOT NULL,
                description VARCHAR(255) NOT NULL
            )
        `);

        for (const year of years) {
            try {
                const response = await fetch(`https://date.nager.at/api/v3/PublicHolidays/${year}/TR`);
                if (!response.ok) continue;

                const holidays = await response.json();
                for (const h of holidays) {
                    await db.execute(
                        `INSERT INTO public_holidays (holiday_date, description) 
                         VALUES (?, ?) 
                         ON CONFLICT (holiday_date) DO UPDATE SET description = EXCLUDED.description`,
                        [h.date, h.localName]
                    );
                }
                console.log(`✅ ${year} yılı resmi/dini tatilleri başarıyla senkronize edildi.`);
            } catch (fetchErr) {
                console.warn(`${year} yılı tatilleri internetten çekilemedi (Offline mod devrede):`, fetchErr.message);
            }
        }
    } catch (err) {
        console.error('Tatil tablosu başlatma hatası:', err.message);
    }
}

// Sunucu başladığında arka planda tatilleri kontrol et ve güncelle
syncPublicHolidays([2026, 2027]);

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
    const privilegedRoles = ['admin', 'webmaster', 'coordinator'];
    if (privilegedRoles.includes(req.user.role)) {
        return next();
    }
    if (String(req.user.id) !== String(req.params.id)) {
        return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece kendi verilerinize erişebilirsiniz.' });
    }
    next();
};

// --- 5. API ENDPOINT'LERİ ---

// [1] GÜVENLİ GİRİŞ (Personel ve Öğrenci)
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { identifier, password, loginType } = req.body || {};

    if (!identifier || !password) {
        return res.status(400).json({ message: 'Lütfen kullanıcı adı / e-posta ve şifrenizi girin.' });
    }

    try {
        let queryParam = identifier.trim();

        if (loginType === 'staff') {
            const [rows] = await db.execute(`
                SELECT * FROM users 
                WHERE (LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?)) 
                  AND role IN ('admin', 'coordinator', 'supervisor')
            `, [queryParam, queryParam]);

            if (rows.length === 0) {
                return res.status(401).json({ message: 'Personel kaydı bulunamadı veya yetkisiz rol.' });
            }

            const user = rows[0];
            const isBcryptHash = user.password_hash && /^\$2[aby]\$/.test(user.password_hash);
            if (!isBcryptHash) {
                return res.status(500).json({ message: 'Hesap şifre format hatası. Yöneticinizle iletişime geçin.' });
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
            const [rows] = await db.execute(`
                SELECT * FROM users 
                WHERE (student_no = ? OR LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)) 
                  AND role = 'student'
            `, [queryParam, queryParam, queryParam]);

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

// [1.1] KULLANICI ŞİFRE DEĞİŞTİRME
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const userId = req.user.id;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Mevcut şifre ve yeni şifre zorunludur.' });
    }

    if (newPassword.trim().length < 4) {
        return res.status(400).json({ message: 'Yeni şifre en az 4 karakter olmalıdır.' });
    }

    try {
        const [rows] = await db.execute('SELECT password_hash FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, rows[0].password_hash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Mevcut şifrenizi hatalı girdiniz.' });
        }

        const newHash = await bcrypt.hash(newPassword.trim(), 10);
        await db.execute('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, userId]);

        await createAuditLog(userId, 'PASSWORD_CHANGE', userId, null, null, req.ip);

        res.json({ message: 'Şifreniz başarıyla değiştirildi.' });
    } catch (error) {
        console.error('Şifre Değiştirme Hatası:', error);
        res.status(500).json({ message: 'Şifre güncellenirken sunucu hatası oluştu.' });
    }
});

// [1.2] ADMIN: KULLANICI ŞİFRESİ SIFIRLAMA
app.post('/api/admin/users/:id/reset-password', authenticateToken, authorizeRoles('admin', 'webmaster'), async (req, res) => {
    try {
        const targetUserId = req.params.id;
        const { newPassword } = req.body || {};

        const tempPassword = (newPassword && newPassword.trim()) ? newPassword.trim() : 'hu_ergo';
        const newHash = await bcrypt.hash(tempPassword, 10);

        await db.execute('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, targetUserId]);
        await createAuditLog(req.user.id, 'ADMIN_PASSWORD_RESET', targetUserId, null, { resetTo: tempPassword }, req.ip);

        res.json({ message: `Şifre başarıyla sıfırlandı. Yeni geçici şifre: ${tempPassword}` });
    } catch (err) {
        console.error('Şifre Sıfırlama Hatası:', err);
        res.status(500).json({ message: 'Şifre sıfırlanamadı.' });
    }
});

// [1.3] KULLANICI KENDİ PROFİLİNİ GÜNCELLEME
app.post('/api/auth/update-profile', authenticateToken, async (req, res) => {
    const { email, username } = req.body || {};
    const userId = req.user.id;

    if (!email || !email.trim()) {
        return res.status(400).json({ message: 'Geçerli bir e-posta adresi giriniz.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanUsername = username ? username.trim().toLowerCase() : null;
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
        return res.status(400).json({ message: 'Lütfen geçerli formatta bir e-posta adresi yazın.' });
    }

    try {
        const [existingEmail] = await db.execute(
            'SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND id != ?',
            [cleanEmail, userId]
        );
        if (existingEmail.length > 0) {
            return res.status(400).json({ message: 'Bu e-posta adresi başka bir kullanıcı tarafından kullanılıyor.' });
        }

        if (cleanUsername) {
            const [existingUsername] = await db.execute(
                'SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?',
                [cleanUsername, userId]
            );
            if (existingUsername.length > 0) {
                return res.status(400).json({ message: 'Bu kullanıcı adı başka bir personel tarafından kullanılıyor.' });
            }
        }

        const [userRows] = await db.execute('SELECT email, username FROM users WHERE id = ?', [userId]);
        const oldData = userRows[0] || {};

        if (cleanUsername) {
            await db.execute('UPDATE users SET email = ?, username = ? WHERE id = ?', [cleanEmail, cleanUsername, userId]);
        } else {
            await db.execute('UPDATE users SET email = ? WHERE id = ?', [cleanEmail, userId]);
        }

        await createAuditLog(userId, 'PROFILE_UPDATE', userId, oldData, { email: cleanEmail, username: cleanUsername }, req.ip);

        res.json({ 
            message: 'Profil bilgileriniz başarıyla güncellendi.', 
            email: cleanEmail, 
            username: cleanUsername 
        });
    } catch (error) {
        console.error('Profil Güncelleme Hatası:', error);
        res.status(500).json({ message: 'Profil güncellenirken sunucu hatası oluştu.' });
    }
});

// [1.4] ADMIN: TATİLLERİ MANUEL TETİKLEME
app.post('/api/admin/sync-holidays', authenticateToken, authorizeRoles('admin', 'webmaster'), async (req, res) => {
    const currentYear = new Date().getFullYear();
    await syncPublicHolidays([currentYear, currentYear + 1]);
    res.json({ message: `${currentYear} ve ${currentYear + 1} yılları resmi ve dini bayramları başarıyla güncellendi.` });
});

// [2] SÜPERVİZÖRÜN KENDİ ÜNİTESİNDEKİ ÖĞRENCİLER
app.get('/api/supervisors/:id/students', authenticateToken, authorizeRoles('supervisor', 'admin', 'coordinator'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = parseInt(req.params.id, 10);
        
        const [students] = await db.execute(`
            SELECT 
                id, 
                name, 
                student_no, 
                internship_id,
                course_code,
                course_name,
                internship_type,
                start_date,
                end_date,
                required_days,
                my_department_name,
                session_type,
                total_score,
                rubric_details,
                eval_note,
                approved_days,
                pending_days,
                department_approved
            FROM supervisor_my_students_view
            WHERE supervisor_id = ?
            ORDER BY course_code ASC, name ASC
        `, [supervisorId]);

        res.json(students);
    } catch (error) {
        console.error('Süpervizör Öğrenci Hatası:', error);
        res.status(500).json({ message: 'Öğrenci listesi çekilemedi.' });
    }
});

// [3] SÜPERVİZÖRÜN SORUMLU OLDUĞU ÖĞRENCİLERİN YOKLAMALARI
app.get('/api/supervisors/:id/attendances', authenticateToken, authorizeRoles('supervisor', 'admin', 'coordinator'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = parseInt(req.params.id, 10);
        
        const [attendances] = await db.execute(`
            SELECT DISTINCT
                a.*, 
                v.name as student_name, 
                v.student_no, 
                v.course_code,
                v.internship_type,
                v.my_department_name,
                v.session_type
            FROM attendances a
            JOIN supervisor_my_students_view v ON a.student_id = v.id
            WHERE v.supervisor_id = ?
            ORDER BY a.id DESC
        `, [supervisorId]);

        res.json(attendances);
    } catch (error) {
        console.error('Yoklama Listesi Hatası:', error);
        res.status(500).json({ message: 'Yoklama listesi çekilemedi.' });
    }
});

// [4] YOKLAMA DURUM GÜNCELLEME
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

        res.json({ message: 'Yoklama durumu güncellendi.' });
    } catch (error) {
        console.error('Yoklama Güncelleme Hatası:', error);
        res.status(500).json({ message: 'Yoklama durumu güncellenemedi.' });
    }
});

// [5] TOPLU YOKLAMA ONAYLAMA
app.post('/api/supervisors/:id/approve-all', authenticateToken, authorizeRoles('supervisor', 'admin'), requireOwnIdOrPrivileged, async (req, res) => {
    try {
        const supervisorId = parseInt(req.params.id, 10);
        
        await db.execute(`
            UPDATE attendances
            SET status = 'approved'
            WHERE student_id IN (
                SELECT DISTINCT id FROM supervisor_my_students_view WHERE supervisor_id = ?
            )
            AND status = 'pending'
        `, [supervisorId]);

        await createAuditLog(req.user.id, 'BULK_ATTENDANCE_APPROVE', null, null, { supervisorId }, req.ip);

        res.json({ message: 'Tüm bekleyen yoklamalar onaylandı.' });
    } catch (error) {
        console.error('Toplu Onay Hatası:', error);
        res.status(500).json({ message: 'Toplu onay işlemi başarısız.' });
    }
});

// [6] GÜNLÜK YOKLAMA (Öğrenci Check-in - Dini/Resmi Tatil Korumalı)
app.post('/api/attendance/check-in', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    const studentId = req.user.id;
    const { locationInfo } = req.body || {};
    
    const now = new Date();
    const dayOfWeek = now.getDay();
    const currentHour = now.getHours();
    const dateStr = now.toISOString().split('T')[0];
    const timeStr = now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });

    try {
        // 1. Resmi ve Dini Tatil Kontrolü
        const [holidayRows] = await db.execute(
            'SELECT description FROM public_holidays WHERE holiday_date = ?',
            [dateStr]
        );
        if (holidayRows.length > 0) {
            return res.status(400).json({ 
                message: `Bugün resmi tatildir (${holidayRows[0].description}). Yoklama alınmamaktadır.` 
            });
        }

        const [internshipRows] = await db.execute('SELECT internship_type FROM internships WHERE student_id = ?', [studentId]);
        const isInternal = internshipRows.some(r => r.internship_type === 'internal');

        let sessionType = 'full_day';

        if (isInternal) {
            if (![2, 3, 4, 5].includes(dayOfWeek)) {
                return res.status(400).json({ message: 'Okul içi staj günleri Salı, Çarşamba, Perşembe ve Cuma günleridir.' });
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

// [7] MAZERETLİ YOKLAMA TALEBİ
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

        res.json({ message: 'Mazeretli yoklama talebiniz iletildi.' });
    } catch (error) {
        console.error('Mazeret Hatası:', error);
        res.status(500).json({ message: 'Mazeretli yoklama talebi kaydedilemedi.' });
    }
});

// [8] ÖĞRENCİ PANELİ VERİLERİ (Bölüm Onayı Şartlı Not Güvenliği)
app.get('/api/student/data', authenticateToken, authorizeRoles('student', 'admin'), async (req, res) => {
    try {
        const studentId = req.user.id;

        const [users] = await db.execute(`
            SELECT u.id, u.name, u.student_no, u.email, u.department_approved, adv.name as advisor_name
            FROM users u
            LEFT JOIN users adv ON u.advisor_id = adv.id
            WHERE u.id = ?
        `, [studentId]);
        const studentData = users[0] || {};

        const isApproved = studentData.department_approved == 1;

        const [internships] = await db.execute(`
            SELECT 
                i.*, 
                dept_m.name as morning_dept_name,
                dept_a.name as afternoon_dept_name,
                sup.name as supervisor_name,
                -- Sadece koordinatör resmi onay vermişse notu döndür
                CASE WHEN ? = 1 THEN g.total_score ELSE NULL END as total_score,
                CASE WHEN ? = 1 THEN g.rubric_details ELSE NULL END as rubric_details,
                CASE WHEN ? = 1 THEN g.note ELSE NULL END as grade_note
            FROM internships i
            LEFT JOIN departments dept_m ON i.morning_dept_id = dept_m.id
            LEFT JOIN departments dept_a ON i.afternoon_dept_id = dept_a.id
            LEFT JOIN users sup ON i.supervisor_id = sup.id
            LEFT JOIN grades g ON (g.student_id = i.student_id AND g.course_code = i.course_code)
            WHERE i.student_id = ?
            ORDER BY i.course_code ASC
        `, [isApproved ? 1 : 0, isApproved ? 1 : 0, isApproved ? 1 : 0, studentId]);

        const [attendances] = await db.execute(`
            SELECT * FROM attendances WHERE student_id = ? ORDER BY id DESC
        `, [studentId]);

        const primaryInternship = internships[0] || {};

        const responseData = {
            ...studentData,
            ...primaryInternship,
            internships,
            attendances,
            approved_days: attendances.filter(a => a.status === 'approved').length
        };

        res.json(responseData);
    } catch (error) {
        console.error('Öğrenci Veri Hatası:', error);
        res.status(500).json({ message: 'Öğrenci verileri çekilemedi.' });
    }
});


// --- DİNAMİK STAJ DÖNEMLERİ VE TARİHLERİ LİSTESİ ---
app.get('/api/internships/periods', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT DISTINCT 
                course_code,
                TO_CHAR(start_date, 'YYYY-MM-DD') as start_date,
                TO_CHAR(end_date, 'YYYY-MM-DD') as end_date
            FROM internships
            WHERE start_date IS NOT NULL AND end_date IS NOT NULL
            ORDER BY start_date ASC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Dönem listesi çekilemedi:', error);
        res.status(500).json({ message: 'Staj dönemleri getirilemedi.' });
    }
});

// [9] STAJ KOORDİNATÖRÜ: TÜM ÖĞRENCİLER VE TÜM STAJLAR (LEFT JOIN Desteği)
app.get('/api/coordinator/students', authenticateToken, authorizeRoles('coordinator', 'admin'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT 
                u.id, 
                u.name, 
                u.student_no, 
                u.department_approved,
                i.id as internship_id,
                COALESCE(i.course_code, 'Atanmadı') as course_code,
                COALESCE(i.course_name, 'Mesleki Uygulama') as course_name,
                COALESCE(i.internship_type, 'internal') as internship_type,
                COALESCE(i.required_days, 20) as required_days,
                i.start_date,
                i.end_date,
                dept_m.name as morning_dept_name,
                dept_a.name as afternoon_dept_name,
                sup.name as supervisor_name,
                g.total_score,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.status = 'approved') as approved_attendance_count,
                (SELECT COUNT(*) FROM attendances a WHERE a.student_id = u.id AND a.is_retroactive = 1) as retroactive_count
            FROM users u
            LEFT JOIN internships i ON u.id = i.student_id
            LEFT JOIN departments dept_m ON i.morning_dept_id = dept_m.id
            LEFT JOIN departments dept_a ON i.afternoon_dept_id = dept_a.id
            LEFT JOIN users sup ON i.supervisor_id = sup.id
            LEFT JOIN grades g ON (g.student_id = u.id AND g.course_code = i.course_code)
            WHERE u.role = 'student'
            ORDER BY u.name ASC, i.course_code ASC
        `);

        res.json(rows);
    } catch (error) {
        console.error('Koordinatör Öğrenci Listesi Hatası:', error);
        res.status(500).json({ message: 'Bölüm verileri çekilemedi.' });
    }
});

// [10] STAJ KOORDİNATÖRÜ: ÖĞRENCİ YOKLAMA DETAYI
app.get('/api/coordinator/attendances/:studentId', authenticateToken, authorizeRoles('coordinator', 'admin'), async (req, res) => {
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

// [12] ADMIN: ÖĞRENCİ VE ÇOKLU STAJ DÖNEMİ / ROTASYONU KAYDI
app.post('/api/admin/students/save', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { students } = req.body || {};

    if (!Array.isArray(students) || students.length === 0) {
        return res.status(400).json({ message: 'Geçerli öğrenci verisi bulunamadı.' });
    }

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        for (const stu of students) {
            const baseSlug = slugifyName(stu.name);
            let stuEmail = (stu.email && stu.email.trim() !== '') ? stu.email.trim().toLowerCase() : null;

            if (!stuEmail) {
                stuEmail = `${baseSlug}@ergo.local`;
                const [coll] = await connection.execute(
                    'SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND student_no != ?', 
                    [stuEmail, stu.studentNo]
                );
                if (coll.length > 0) {
                    stuEmail = `${baseSlug}.${stu.studentNo}@ergo.local`;
                }
            }

            const stuUsername = (stu.username && stu.username.trim() !== '') ? stu.username.trim().toLowerCase() : stu.studentNo;

            // 1. Kullanıcı tekilleştirme
            let [existing] = await connection.execute('SELECT id FROM users WHERE student_no = ?', [stu.studentNo]);
            let studentId;

            if (existing.length > 0) {
                studentId = existing[0].id;
                if (stu.password && stu.password.trim() !== '') {
                    const newHash = await bcrypt.hash(stu.password.trim(), 10);
                    await connection.execute(
                        'UPDATE users SET name = ?, email = COALESCE(email, ?), username = COALESCE(username, ?), password_hash = ? WHERE id = ?',
                        [stu.name, stuEmail, stuUsername, newHash, studentId]
                    );
                } else {
                    await connection.execute(
                        'UPDATE users SET name = ?, email = COALESCE(email, ?), username = COALESCE(username, ?) WHERE id = ?',
                        [stu.name, stuEmail, stuUsername, studentId]
                    );
                }
            } else {
                const defaultHash = await bcrypt.hash(stu.password || '1234', 10);
                const [insertRes] = await connection.execute(
                    "INSERT INTO users (name, student_no, email, username, password_hash, role) VALUES (?, ?, ?, ?, ?, 'student') RETURNING id",
                    [stu.name, stu.studentNo, stuEmail, stuUsername, defaultHash]
                );
                studentId = insertRes[0].id;
            }

            // 2. Çoklu rotasyon / dönem desteği
            const internshipsArray = Array.isArray(stu.internships) ? stu.internships : [stu];

            for (const item of internshipsArray) {
                const courseCode = (item.courseCode || stu.courseCode || 'Staj 1').trim();
                const courseName = item.courseName || stu.courseName || 'Mesleki Uygulama';
                const internshipType = item.internshipType || stu.internshipType || 'internal';
                const morningDept = item.morningDeptId || stu.morningDeptId || null;
                const afternoonDept = item.afternoonDeptId || stu.afternoonDeptId || morningDept;
                const supervisorId = item.supervisorId || stu.supervisorId || null;
                const requiredDays = item.requiredDays || stu.requiredDays || 20;
                const startDate = item.startDate || stu.startDate || '2026-09-14';
                const endDate = item.endDate || stu.endDate || '2026-10-18';

                await connection.execute(`
                    INSERT INTO internships (
                        student_id, course_code, course_name, internship_type, 
                        start_date, end_date, required_days, supervisor_id, morning_dept_id, afternoon_dept_id
                    ) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (student_id, course_code) DO UPDATE SET 
                        course_name = EXCLUDED.course_name,
                        internship_type = EXCLUDED.internship_type,
                        start_date = EXCLUDED.start_date,
                        end_date = EXCLUDED.end_date,
                        required_days = EXCLUDED.required_days,
                        supervisor_id = EXCLUDED.supervisor_id,
                        morning_dept_id = EXCLUDED.morning_dept_id,
                        afternoon_dept_id = EXCLUDED.afternoon_dept_id
                `, [
                    studentId,
                    courseCode,
                    courseName,
                    internshipType,
                    startDate,
                    endDate,
                    requiredDays,
                    supervisorId,
                    morningDept,
                    afternoonDept
                ]);
            }
        }

        await connection.commit();
        res.json({ message: 'Öğrenciler ve tüm staj dönemleri başarıyla kaydedildi.' });
    } catch (err) {
        await connection.rollback();
        console.error('Öğrenci Kayıt Hatası:', err);
        res.status(500).json({ message: 'Kayıt sırasında veritabanı hatası oluştu.' });
    } finally {
        connection.release();
    }
});

// [12.1] ADMIN: DIŞ STAJ ÖĞRENCİ VE SÜPERVİZÖR TOPLU KAYDI
app.post('/api/admin/students/save-external', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { students } = req.body || {};

    if (!Array.isArray(students) || students.length === 0) {
        return res.status(400).json({ message: 'Geçerli dış staj verisi bulunamadı.' });
    }

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        for (const stu of students) {
            let supervisorId = null;
            const hasSupName = stu.supervisorName && stu.supervisorName.trim() !== '';
            const hasSupEmail = stu.supervisorEmail && stu.supervisorEmail.trim() !== '';

            if (hasSupName || hasSupEmail) {
                const baseSlug = slugifyName(stu.supervisorName || 'supervizor');
                const supEmail = hasSupEmail ? stu.supervisorEmail.trim().toLowerCase() : `${baseSlug}@ergo.local`;
                const supUsername = baseSlug;

                const [existingSup] = await connection.execute(
                    `SELECT id FROM users 
                     WHERE LOWER(email) = LOWER(?) 
                        OR (LOWER(name) = LOWER(?) AND role = 'supervisor')
                     LIMIT 1`, 
                    [supEmail, (stu.supervisorName || '').trim()]
                );

                if (existingSup.length > 0) {
                    supervisorId = existingSup[0].id;
                    if (stu.institutionName) {
                        await connection.execute('UPDATE users SET department = ? WHERE id = ?', [stu.institutionName, supervisorId]);
                    }
                } else {
                    const defaultSupHash = await bcrypt.hash('hu_ergo', 10);
                    const [insertSup] = await connection.execute(
                        `INSERT INTO users (name, email, username, password_hash, role, department) 
                         VALUES (?, ?, ?, ?, 'supervisor', ?) RETURNING id`,
                        [stu.supervisorName || 'Dış Süpervizör', supEmail, supUsername, defaultSupHash, stu.institutionName || 'Dış Kurum']
                    );
                    supervisorId = insertSup[0].id;
                }
            }

            const stuBaseSlug = slugifyName(stu.name);
            let stuEmail = (stu.studentEmail && stu.studentEmail.trim() !== '') ? stu.studentEmail.trim().toLowerCase() : null;

            if (!stuEmail) {
                stuEmail = `${stuBaseSlug}@ergo.local`;
                const [coll] = await connection.execute(
                    'SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND student_no != ?', 
                    [stuEmail, stu.studentNo]
                );
                if (coll.length > 0) {
                    stuEmail = `${stuBaseSlug}.${stu.studentNo}@ergo.local`;
                }
            }
            const stuUsername = stu.studentNo;

            let [existingStu] = await connection.execute('SELECT id FROM users WHERE student_no = ?', [stu.studentNo]);
            let studentId;

            if (existingStu.length > 0) {
                studentId = existingStu[0].id;
                await connection.execute(
                    'UPDATE users SET name = ?, email = COALESCE(?, email), username = COALESCE(username, ?), supervisor_id = ?, internship_type = ? WHERE id = ?',
                    [stu.name, stuEmail, stuUsername, supervisorId, 'external', studentId]
                );
            } else {
                const stuHash = await bcrypt.hash(stu.password || '1234', 10);
                const [insertStu] = await connection.execute(
                    `INSERT INTO users (name, student_no, email, username, password_hash, role, supervisor_id, internship_type) 
                     VALUES (?, ?, ?, ?, ?, 'student', ?, 'external') RETURNING id`,
                    [stu.name, stu.studentNo, stuEmail, stuUsername, stuHash, supervisorId]
                );
                studentId = insertStu[0].id;
            }

            const internshipsArray = Array.isArray(stu.internships) ? stu.internships : [stu];

            for (const item of internshipsArray) {
                const courseCode = (item.courseCode || stu.courseCode || 'Staj 1').trim();
                const startDate = item.startDate || stu.startDate || '2026-09-14';
                const endDate = item.endDate || stu.endDate || '2026-10-18';
                const requiredDays = item.requiredDays || stu.requiredDays || 20;

                await connection.execute(`
                    INSERT INTO internships (
                        student_id, course_code, course_name, internship_type, 
                        start_date, end_date, required_days, supervisor_id, morning_dept_id, afternoon_dept_id
                    ) 
                    VALUES (?, ?, ?, 'external', ?, ?, ?, ?, NULL, NULL)
                    ON CONFLICT (student_id, course_code) DO UPDATE SET 
                        internship_type = 'external',
                        start_date = EXCLUDED.start_date,
                        end_date = EXCLUDED.end_date,
                        required_days = EXCLUDED.required_days,
                        supervisor_id = EXCLUDED.supervisor_id,
                        morning_dept_id = NULL,
                        afternoon_dept_id = NULL
                `, [
                    studentId,
                    courseCode,
                    'Dış Kurum Mesleki Uygulama',
                    startDate,
                    endDate,
                    requiredDays,
                    supervisorId
                ]);
            }
        }

        await connection.commit();
        res.json({ message: 'Dış staj öğrencileri ve tüm rotasyonları başarıyla kaydedildi.' });
    } catch (err) {
        await connection.rollback();
        console.error('Dış Staj Kayıt Hatası:', err);
        res.status(500).json({ message: 'Kayıt sırasında veritabanı hatası oluştu.' });
    } finally {
        connection.release();
    }
});

// [13] ADMIN: PERSONEL (SÜPERVİZÖR) KAYDI
app.post('/api/admin/supervisors/save', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { name, email, username, password, role } = req.body || {};

    if (!name || name.trim() === '') {
        return res.status(400).json({ message: 'Personel adı zorunludur.' });
    }

    const baseSlug = slugifyName(name);
    const cleanUsername = (username && username.trim() !== '') ? username.trim().toLowerCase() : baseSlug;
    const cleanEmail = (email && email.trim() !== '') ? email.trim().toLowerCase() : `${baseSlug}@ergo.local`;

    const requesterIsAdmin = req.user.role === 'admin' || req.user.role === 'webmaster';
    const requestedRole = role || 'supervisor';

    const PRIVILEGED_ROLES = ['admin', 'webmaster', 'coordinator'];
    if (!requesterIsAdmin && PRIVILEGED_ROLES.includes(requestedRole)) {
        return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece yönetici üst yetki tanımlayabilir.' });
    }
    const assignedRole = requesterIsAdmin ? requestedRole : 'supervisor';

    try {
        const [existing] = await db.execute(
            'SELECT id, role FROM users WHERE LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?) OR (LOWER(name) = LOWER(?) AND role = ?)', 
            [cleanEmail, cleanUsername, name.trim(), assignedRole]
        );

        if (existing.length > 0) {
            if (password && password.trim() !== '') {
                const newHash = await bcrypt.hash(password.trim(), 10);
                await db.execute(
                    'UPDATE users SET name = ?, username = ?, email = ?, role = ?, password_hash = ? WHERE id = ?',
                    [name.trim(), cleanUsername, cleanEmail, assignedRole, newHash, existing[0].id]
                );
            } else {
                await db.execute(
                    'UPDATE users SET name = ?, username = ?, email = ?, role = ? WHERE id = ?',
                    [name.trim(), cleanUsername, cleanEmail, assignedRole, existing[0].id]
                );
            }
            res.json({ message: 'Personel bilgileri güncellendi.' });
        } else {
            const defaultHash = await bcrypt.hash(password || 'hu_ergo', 10);
            await db.execute(
                'INSERT INTO users (name, email, username, password_hash, role) VALUES (?, ?, ?, ?, ?)',
                [name.trim(), cleanEmail, cleanUsername, defaultHash, assignedRole]
            );
            res.json({ message: 'Yeni personel başarıyla sisteme eklendi.' });
        }
    } catch (err) {
        console.error('Personel Kayıt Hatası:', err);
        res.status(500).json({ message: 'Personel kaydı sırasında hata oluştu.' });
    }
});

// [14] ADMIN: PERSONEL LİSTESİ
app.get('/api/admin/supervisors', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT id, name, email, username, role, created_at 
            FROM users 
            WHERE role IN ('supervisor', 'coordinator') 
            ORDER BY name ASC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Süpervizör Listeleme Hatası:', error);
        res.status(500).json({ message: 'Personel listesi çekilemedi.' });
    }
});

// [14.1] TÜM DEPARTMANLARI LİSTELE
app.get('/api/admin/departments', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    try {
        const [depts] = await db.execute('SELECT * FROM departments ORDER BY id ASC');
        const [assignments] = await db.execute(`
            SELECT ds.department_id, u.id as user_id, u.name as user_name, u.email 
            FROM department_supervisors ds
            JOIN users u ON COALESCE(ds.supervisor_id, ds.user_id) = u.id
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

// [14.2] DEPARTMANA HOCA ATA
app.post('/api/admin/departments/assign', authenticateToken, authorizeRoles('admin', 'webmaster', 'coordinator'), async (req, res) => {
    const { departmentId, supervisorId } = req.body || {};
    if (!departmentId || !supervisorId) {
        return res.status(400).json({ message: 'Departman ve hoca seçimi zorunludur.' });
    }

    try {
        await db.execute(
            `INSERT INTO department_supervisors (department_id, supervisor_id, user_id) 
             VALUES (?, ?, ?) 
             ON CONFLICT (department_id, user_id) DO UPDATE SET supervisor_id = EXCLUDED.supervisor_id`,
            [departmentId, supervisorId, supervisorId]
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
            'DELETE FROM department_supervisors WHERE department_id = ? AND (supervisor_id = ? OR user_id = ?)',
            [departmentId, supervisorId, supervisorId]
        );
        res.json({ message: 'Hoca departmandan çıkarıldı.' });
    } catch (error) {
        console.error('Departmandan hoca çıkarma hatası:', error);
        res.status(500).json({ message: 'İşlem başarısız.' });
    }
});

// [15] DERS BAZLI NOT GİRİŞİ / DÜZENLEME
app.post('/api/grades/assign', authenticateToken, authorizeRoles('supervisor', 'coordinator', 'admin'), async (req, res) => {
    const evaluatorId = req.user.id;
    const { studentId, courseCode, totalScore, rubricDetails, note } = req.body || {};

    if (!studentId || !courseCode) {
        return res.status(400).json({ message: 'Öğrenci ve ders kodu zorunludur.' });
    }

    try {
        if (req.user.role === 'supervisor') {
            const [permCheck] = await db.execute(`
                SELECT id FROM supervisor_my_students_view 
                WHERE id = ? AND supervisor_id = ? AND course_code = ?
            `, [studentId, evaluatorId, courseCode]);

            if (permCheck.length === 0) {
                await createAuditLog(evaluatorId, 'UNAUTHORIZED_GRADE_ATTEMPT', studentId, null, { attemptedScore: totalScore, courseCode }, req.ip);
                return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Bu ders için değerlendirme yetkiniz bulunmamaktadır!' });
            }
        }

        const [oldGradeRows] = await db.execute(
            'SELECT * FROM grades WHERE student_id = ? AND course_code = ?', 
            [studentId, courseCode]
        );
        const oldGrade = oldGradeRows[0] || null;

        const cleanRubric = typeof rubricDetails === 'object' ? rubricDetails : {};

        await db.execute(`
            INSERT INTO grades (student_id, evaluator_id, course_code, total_score, rubric_details, note) 
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (student_id, course_code) DO UPDATE SET 
                evaluator_id = EXCLUDED.evaluator_id,
                total_score = EXCLUDED.total_score,
                rubric_details = EXCLUDED.rubric_details,
                note = EXCLUDED.note,
                updated_at = CURRENT_TIMESTAMP
        `, [studentId, evaluatorId, courseCode, totalScore, cleanRubric, note]);

        await createAuditLog(
            evaluatorId, 
            oldGrade ? 'GRADE_UPDATE' : 'GRADE_CREATE', 
            studentId, 
            oldGrade, 
            { courseCode, totalScore, rubricDetails: cleanRubric, note }, 
            req.ip
        );

        res.json({ message: 'Staj notu başarıyla kaydedildi.' });
    } catch (error) {
        console.error('Not Kayıt Hatası:', error);
        res.status(500).json({ message: 'Not kaydı sırasında sunucu hatası oluştu.' });
    }
});

// [16] ÖĞRENCİ DETAYLI NOTUNU GETİRME (Öğrenci sorgusunda onay kontrolü)
app.get('/api/grades/student/:studentId', authenticateToken, async (req, res) => {
    try {
        const studentId = req.params.studentId;
        const currentUserId = req.user.id;
        const currentUserRole = req.user.role;

        if (currentUserRole === 'student') {
            if (String(currentUserId) !== String(studentId)) {
                return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Sadece kendi notunuzu görüntüleyebilirsiniz.' });
            }

            const [uRows] = await db.execute('SELECT department_approved FROM users WHERE id = ?', [studentId]);
            if (uRows.length === 0 || uRows[0].department_approved != 1) {
                return res.status(403).json({ message: 'Staj notunuz henüz Bölüm Koordinatörlüğü tarafından resmi olarak onaylanmamıştır.' });
            }
        }

        if (currentUserRole === 'supervisor') {
            const [ownership] = await db.execute(`
                SELECT id FROM supervisor_my_students_view 
                WHERE id = ? AND supervisor_id = ?
            `, [studentId, currentUserId]);

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

        res.json(rows);
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