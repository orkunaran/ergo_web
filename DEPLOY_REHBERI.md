# Deploy Rehberi — Vercel + Supabase

## 1) Silinmesi Gereken Dosya
`init-db.js` varsa **silin** — eski MySQL şeması, artık kullanılmıyor. Kurulum için `setup_db.js` kullanılıyor (bkz. `KURULUM.md`).

## 2) Yerel Kurulum
Adım adım kurulum için `KURULUM.md` dosyasına bakın (Supabase projesi oluşturma, `.env` ayarları, şema kurulumu).

## 3) Vercel'e Deploy
1. Projeyi bir GitHub reposuna yükleyin (`.env` dosyasını **YÜKLEMEYİN** — `.gitignore` zaten hariç tutuyor).
2. Vercel'de "New Project" ile bu repoyu içe aktarın. Framework "Other" seçilebilir, ek build ayarı gerekmez.
3. Vercel Dashboard → Project → Settings → Environment Variables kısmına şunları ekleyin:
   - `DATABASE_URL` — Supabase'in "Transaction pooler" bağlantı string'i (bkz. `KURULUM.md` Adım 1)
   - `DATABASE_SSL_STRICT=false` (veya sıkı doğrulama istiyorsanız `true` + `DATABASE_CA`)
   - `DB_POOL_MAX=3`
   - `JWT_SECRET` (rastgele üretilmiş, uzun bir değer)
   - `ALLOWED_ORIGINS` (örn. `https://ergostaj.vercel.app` — deploy sonrası Vercel'in verdiği gerçek adres)
4. Deploy edin. Vercel `/api/index.js`'i serverless fonksiyon, kök dizindeki `.html` dosyalarını statik dosya olarak sunar.

## 4) Neden Artık "Sabit IP" Sorunu Yok
Önceki (üniversite MySQL) mimarisinde Vercel'in sabit bir çıkış IP'si olmaması büyük bir sorundu.
Supabase'e geçtiğimiz için bu sorun ortadan kalktı: Supabase'in Supavisor connection pooler'ı
(Transaction mode, port 6543) tam olarak bu senaryo — serverless fonksiyonlardan gelen çok sayıda
kısa ömürlü bağlantı — için tasarlandı. IP allowlist'e ihtiyaç yok, ekstra bir "geçit sunucusu"
kurmanıza gerek kalmadı.

## 5) Bu Geçişte Yapılan Değişikliklerin Özeti
- **Veritabanı**: MySQL (üniversite sunucusu) → PostgreSQL (Supabase). `mysql2` kütüphanesi
  kaldırıldı, `pg` eklendi.
- **`db.js`** adında yeni bir uyumluluk katmanı eklendi: `app.js`'teki mevcut
  `db.execute(sql, params)` çağrıları neredeyse hiç değişmeden çalışıyor; katman `?`
  placeholder'larını Postgres'in `$1, $2...` biçimine otomatik çeviriyor.
- **Şema farkları** düzeltildi: `AUTO_INCREMENT` → `GENERATED ALWAYS AS IDENTITY`, `ENUM` →
  `TEXT + CHECK`, `JSON` → `JSONB`, `ON DUPLICATE KEY UPDATE` → `ON CONFLICT ... DO UPDATE`,
  MySQL'e özgü çok tablolu `UPDATE ... JOIN` → Postgres'in `UPDATE ... FROM` sözdizimi.
- **Row Level Security (RLS)**: Tüm tablolarda açıldı, hiçbir politika tanımlanmadı (varsayılan:
  erişim reddedilir). Bu, Supabase'in otomatik REST API'si yanlışlıkla bu tablolara açılırsa
  bile veri sızıntısını önleyen bir savunma katmanı. Uygulamanın kendisi (backend bağlantısı)
  RLS'i bypass ettiği için normal çalışmaya devam ediyor.
- Önceki turlarda yapılan tüm güvenlik düzeltmeleri (IDOR kapatma, JWT_SECRET zorunluluğu, XSS
  escape, CORS, rate limiting, Helmet/CSP) korunuyor — bunlar veritabanından bağımsız,
  hâlâ geçerli.

## 6) Sizin Yapmanız Gerekenler
- Supabase projesini oluşturun (bkz. `KURULUM.md` Adım 1) ve `DATABASE_URL`'i alın.
- Vercel'de yukarıdaki ortam değişkenlerini eksiksiz girin.
- `seed.js`'i sadece BOŞ bir test projesinde çalıştırın; gerçek öğrenci verisi olan bir
  projede **asla** çalıştırmayın (tüm kullanıcıları siler).
- Üniversitenizin öğrenci verisinin Supabase'de (üçüncü taraf, genelde yurt dışı barındırma)
  saklanması konusunda KVKK/BİDB onayının alındığından emin olun — bu konuyu daha önce
  konuşmuştuk, teknik geçiş bu onayın yerine geçmez.
