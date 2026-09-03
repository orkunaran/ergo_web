// YEREL GELİŞTİRME İÇİN GİRİŞ NOKTASI
// (Vercel'e deploy ederken bu dosya KULLANILMAZ; onun yerine api/index.js devreye girer.)
require('dotenv').config();
const app = require('./app');

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Yerel geliştirme sunucusu http://127.0.0.1:${PORT} adresinde aktif.`);
});
