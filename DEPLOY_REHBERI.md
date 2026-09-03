# Ergoterapi Staj Takip Sistemi — Kurulum ve Vercel Deploy Rehberi

## 1) Silinmesi Gereken Dosya
`init-db.js` **kullanmayın / silin**. `setup_db.js` ile aynı işi yapıyor ama şeması eski
(internships tablosu ve coordinator/webmaster rolleri yok). Sunucu kodu artık `setup_db.js`'in
şemasına göre yazıldı; `init-db.js` çalıştırılırsa uygulama hata verir.

## 2) Yerel Kurulum
```bash
npm install
cp .env.example .env
# .env dosyasını gerçek DB bilgileriniz ve JWT_SECRET ile doldurun
node setup_db.js          # tabloları oluşturur
ALLOW_SEED=evet-eminim node seed.js   # (opsiyonel) test kullanıcıları oluşturur — şifreler ekrana tek seferlik yazdırılır
npm start                 # http://127.0.0.1:8080
```

`JWT_SECRET` üretmek için:
```bash
openssl rand -hex 32
```

## 3) Vercel'e Deploy
1. Projeyi bir GitHub reposuna yükleyin (`.env` dosyasını **YÜKLEMEYİN** — `.gitignore` zaten hariç tutuyor).
2. Vercel'de "New Project" ile bu repoyu içe aktarın. Framework olarak "Other" seçilebilir, ek build ayarı gerekmez.
3. Vercel Dashboard → Project → Settings → Environment Variables kısmına şunları tek tek ekleyin:
   - `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`, `DB_PORT`
   - `DB_SSL=true` (üniversite sunucusu internete açık olacağı için zorunlu tutulmalı)
   - `DB_CA` (üniversite BİDB TLS sertifikası PEM içeriği verirse)
   - `JWT_SECRET` (adım 2'deki gibi rastgele üretilmiş, uzun bir değer)
   - `ALLOWED_ORIGINS` (örn. `https://ergostaj.vercel.app` — deploy sonrası Vercel'in verdiği gerçek adres)
4. Deploy edin. Vercel `/api/index.js`'i serverless fonksiyon, kök dizindeki `.html` dosyalarını statik dosya olarak sunar.

## 4) Kritik Altyapı Notu — Üniversite MySQL Erişimi
Vercel'in serverless fonksiyonları **sabit bir IP adresinden** bağlanmaz; her çağrı farklı bir
IP havuzundan gelebilir. Üniversitenizin MySQL sunucusu IP bazlı bir güvenlik duvarı (allowlist)
kullanıyorsa bu mimari çalışmaz. Üniversite BİDB (Bilgi İşlem Daire Başkanlığı) ile şu seçeneklerden
birini konuşmanız gerekir:
- MySQL sunucusuna internetten erişimi **zorunlu SSL/TLS + güçlü kullanıcı adı/şifre** ile (IP kısıtlaması
  olmadan) açmak, veya
- Vercel'in ücretli "Secure Compute" (statik IP) özelliğini kullanıp sadece o IP'yi allowlist'e almak, veya
- Aradaki bir bağlantı proxy'si/gateway kullanmak.

Bu, kodla çözülemeyecek bir ağ/altyapı kararıdır — üniversite bilgi işlem birimiyle görüşülmelidir.

## 5) Bu Güncellemede Yapılan Değişikliklerin Özeti
- **IDOR (yetkisiz veri erişimi) açıkları kapatıldı**: süpervizör ve not (grade) endpoint'lerinde artık
  sahiplik kontrolü var.
- **JWT_SECRET hardcoded fallback kaldırıldı**: eksikse sunucu başlamıyor.
- **Düz metin şifre karşılaştırması kaldırıldı**: sadece bcrypt kabul ediliyor.
- **CORS** artık sabit bir domain listesi kullanıyor (`*` değil).
- **Rate limiting** eklendi (login endpoint'i, 15 dk'da 10 deneme).
- **XSS açıkları kapatıldı**: mazeret/not/isim gibi kullanıcı verileri artık HTML'e basılmadan önce
  escape ediliyor; isim gibi veriler artık `onclick` içine ham JS olarak gömülmüyor.
- **Helmet + sıkı CSP** eklendi (sadece kullanılan CDN'lere izin veren güvenlik başlıkları).
- **MySQL bağlantısı**: SSL desteği, zorunlu ortam değişkeni kontrolü, serverless'e uygun düşük
  bağlantı limiti.
- **seed.js**: artık sabit "1234" yerine her kullanıcı için rastgele şifre üretiyor ve yanlışlıkla
  canlı veritabanını silmeye karşı bir onay kilidi var.
- Proje Vercel'de serverless olarak çalışacak şekilde yeniden yapılandırıldı (`app.js` / `server.js` /
  `api/index.js` / `vercel.json`).

## 6) Sizin Yapmanız Gerekenler
- Üniversite BİDB ile MySQL uzak erişimi ve SSL sertifikası konusunu görüşün (bkz. madde 4).
- Vercel'de yukarıdaki ortam değişkenlerini eksiksiz girin.
- `seed.js`'i sadece BOŞ bir test veritabanında çalıştırın; gerçek öğrenci verisi olan bir
  veritabanında **asla** çalıştırmayın (tüm kullanıcıları siler).
- Uzun vadede Tailwind/Font Awesome'ı CDN yerine projeye gömmeyi (self-host) değerlendirin — hem
  performans hem CSP'yi daha da sıkılaştırma açısından faydalı olur.
