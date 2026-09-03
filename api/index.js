// VERCEL SERVERLESS GİRİŞ NOKTASI
// Vercel, /api altındaki her dosyayı ayrı bir serverless fonksiyon olarak çalıştırır.
// Express app'i (req, res) imzasıyla uyumlu olduğu için doğrudan dışa aktarmak yeterlidir.
// vercel.json içindeki "rewrites" kuralı tüm /api/* isteklerini bu fonksiyona yönlendirir.
module.exports = require('../app');
