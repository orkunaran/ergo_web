require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Güvenlik Başlıkları & CORS Ayarları (Arkadaşının 1 ve 5. Maddeleri)
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:3000', // Sadece izin verilen frontend adresi (Canlıda domaininiz olacak)
    credentials: true
}));

// MySQL Bağlantı Havuzu (Arkadaşının 6. Maddesi: Root değil, env değişkenleri ile)
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- YETKİLENDİRME VE GÜVENLİK MİDDLEWARE'LERİ ---

// 1. JWT Doğrulama (Kimlik Kontrolü)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

    if (!token) return res.status(401).json({ message: 'Erişim engellendi, token eksik.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Geçersiz veya süresi dolmuş token.' });
        req.user = user; // Kullanıcı bilgilerini isteğe ekle (id, role vb.)
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

// GÜVENLİ GİRİŞ YAPMA (LOGIN) - Arkadaşının 2. ve 3. Maddeleri
app.post('/api/auth/login', async (req, res) => {
    const { identifier, password, loginType } = req.body; 
    // identifier: Email (Personel için) veya StudentNo (Öğrenci için)

    try {
        let query = '';
        let queryParam = '';

        if (loginType === 'staff') {
            query = 'SELECT * FROM users WHERE email = ? AND role IN ("admin", "academic", "supervisor")';
            queryParam = identifier;
        } else {
            query = 'SELECT * FROM users WHERE student_no = ? AND role = "student"';
            queryParam = identifier;
        }

        // PREPARED STATEMENT (SQL Injection Koruması - Arkadaşının 5. Maddesi)
        const [rows] = await db.execute(query, [queryParam]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Kullanıcı bulunamadı veya hatalı bilgi.' });
        }

        const user = rows[0];

        // Şifre Hash Doğrulama (bcrypt - Arkadaşının 2. Maddesi)
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Hatalı şifre.' });
        }

        // JWT Token Üretme
        const token = jwt.sign(
            { id: user.id, name: user.name, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '8h' } // 8 saat geçerli oturum
        );

        // Hassas verileri (şifre hash'i) yanıttan temizle
        delete user.password_hash;

        res.json({
            message: 'Giriş başarılı',
            token,
            user
        });

    } catch (error) {
        console.error('Login Hata Logu:', error); // Hata sunucu loguna yazılır (Arkadaşının 9. Maddesi)
        res.status(500).json({ message: 'Sunucu hatası oluştu.' }); // Kullanıcıya detay verilmez!
    }
});

// IDOR KORUMALI ÖRNEK ENDPOINT: Öğrenci Notunu Getirme (Arkadaşının 4. Maddesi)
app.get('/api/grades/student/:studentId', authenticateToken, async (req, res) => {
    const targetStudentId = parseInt(req.params.studentId);
    const currentUser = req.user;

    // IDOR KONTROLÜ (Güvenlik Sınırı Sunucuda):
    // İsteği atan kişi öğrenciyse VE sadece kendi ID'sini istemiyorsa ENGELLE!
    if (currentUser.role === 'student' && currentUser.id !== targetStudentId) {
        return res.status(403).json({ message: 'GÜVENLİK İHLALİ: Başka bir öğrencinin notunu göremezsiniz!' });
    }

    try {
        const [grades] = await db.execute('SELECT * FROM grades WHERE student_id = ?', [targetStudentId]);
        res.json(grades[0] || {});
    } catch (error) {
        res.status(500).json({ message: 'Veri çekilemedi.' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Güvenli Backend Sunucusu ${PORT} portunda çalışıyor.`);
});