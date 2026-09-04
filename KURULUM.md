# Kurulum Rehberi — Ergoterapi Staj Takip Sistemi (Supabase Sürümü)

Bu rehber, sistemi Supabase (PostgreSQL) veritabanıyla sıfırdan çalışır hale getirmek için
gereken adımları sırayla anlatır.

---

## Gereksinimler

- **Node.js** 18 veya üzeri ([nodejs.org](https://nodejs.org))
- Bir **Supabase** hesabı ve projesi ([supabase.com](https://supabase.com) — ücretsiz katman yeterli başlangıç için)
- Bir terminal / komut satırı

```bash
node -v
npm -v
```

---

## Adım 1 — Supabase Projesi Oluşturma

1. [supabase.com](https://supabase.com) üzerinden ücretsiz bir hesap açın, "New Project" ile yeni proje oluşturun.
2. Veritabanı şifresini oluştururken **güçlü ve rastgele** bir şifre seçin, bir yere not edin.
3. Proje hazır olduğunda: **Project Settings → Database → Connect** sayfasına gidin.
4. **"Transaction pooler"** (Supavisor, port `6543`) sekmesindeki bağlantı string'ini kopyalayın. Görünümü şuna benzer:
   ```
   postgresql://postgres.xxxxxxxxxxxx:[SIFRENIZ]@aws-0-eu-central-1.pooler.supabase.com:6543/postgres
   ```
   > Neden "Transaction pooler"? Çünkü serverless ortamlar (Vercel gibi) için özel olarak tasarlanmış; her istekte yeni bağlantı açma sorununu Supabase tarafında çözüyor.

---

## Adım 2 — Proje Dosyalarını Hazırlama

```bash
cd ergo-staj
npm install
```

---

## Adım 3 — Ortam Değişkenlerini (.env) Ayarlama

```bash
cp .env.example .env
```

`.env` dosyasını açıp doldurun:

```bash
# Uygulamanın çalışma zamanı sorguları için (Transaction pooler, port 6543)
DATABASE_URL=postgresql://postgres.xxxxxxxxxxxx:GERCEK_SIFRENIZ@aws-1-eu-west-1.pooler.supabase.com:6543/postgres?pgbouncer=true

# Sadece şema kurulumu (setup_db.js) için (Session/Direct bağlantı, port 5432)
DIRECT_URL=postgresql://postgres.xxxxxxxxxxxx:GERCEK_SIFRENIZ@aws-1-eu-west-1.pooler.supabase.com:5432/postgres

DATABASE_SSL_STRICT=false
DB_POOL_MAX=3

JWT_SECRET=
ALLOWED_ORIGINS=http://localhost:8080
PORT=8080
```

**`JWT_SECRET` üretmek için**:
```bash
openssl rand -hex 32
```
Çıkan değeri `.env`'e yapıştırın.

> ⚠️ `.env` dosyasını **asla** GitHub'a veya başka bir yere yüklemeyin.

---

## Adım 4 — Veritabanı Şemasını Oluşturma

```bash
node setup_db.js
```

Başarılı olursa:
```
🎉 Tüm tablolar (users, internships, attendances, grades, audit_logs) eksiksiz oluşturuldu!
🔒 Row Level Security tüm tablolarda etkinleştirildi (varsayılan: erişim reddedilir).
```

Bu adımda `users`, `internships`, `attendances`, `grades`, `audit_logs` tabloları oluşturulur ve
her birinde Row Level Security (RLS) açılır — bu, Supabase'in otomatik API'si yanlışlıkla
etkinleştirilirse dahi hiçbir verinin dışarı sızmamasını garanti eden ek bir güvenlik katmanıdır.
Uygulamanızın kendisi (backend bağlantısı) bundan etkilenmez, normal çalışmaya devam eder.

---

## Adım 5 — (Opsiyonel) Test Kullanıcıları Oluşturma

Sadece **boş bir test/geliştirme projesinde** çalıştırın:

```bash
ALLOW_SEED=evet-eminim node seed.js
```

Şifreler ekrana **tek seferlik** yazdırılır, not edin:
```
⚠️  Aşağıdaki şifreleri şimdi kaydedin — bir daha GÖSTERİLMEYECEK:
┌─────────┬────────────────────────┬──────────────┐
│  Rol    │  Giriş                 │  Şifre       │
├─────────┼────────────────────────┼──────────────┤
│  admin  │  admin@test.com        │  xxxxxxxxxx  │
└─────────┴────────────────────────┴──────────────┘
```

---

## Adım 6 — Sunucuyu Başlatma

```bash
npm start
```

Tarayıcıdan açın: `http://localhost:8080`

---

## Adım 7 — Gerçek Kullanıcıları Ekleme

Test verisiyle işiniz bittiğinde, gerçek kullanıcıları **admin veya koordinatör panelinden** ekleyin:

- **Admin paneli** → süpervizör/personel ekleme, öğrenci + staj tanımı toplu kaydı.
- **Koordinatör paneli** → aynısını yapabilir, ama sadece `supervisor` rolünde kullanıcı oluşturabilir
  (bir koordinatör başka birini admin/koordinatör yapamaz — bu kasıtlı bir güvenlik sınırıdır).

Yeni kullanıcıların varsayılan şifresi `1234`'tür (siz belirtmezseniz). İlk girişten sonra
şifre değiştirmelerini önerin.

---

## Kim Neyi Görebilir? (Hızlı Özet)

| Rol | Görebildikleri |
|---|---|
| **Öğrenci** | Sadece kendi devamsızlık ve not bilgisi |
| **Süpervizör** | Sadece kendisine atanmış öğrenciler |
| **Koordinatör** | Bölümdeki tüm öğrenciler + kullanıcı ekleme (supervisor rolüyle) |
| **Admin** | Her şey + tüm rollerde kullanıcı ekleme/düzenleme |

---

## Sorun Giderme

| Belirti | Olası Sebep |
|---|---|
| "DATABASE_URL ortam değişkeni tanımlı değil" | `.env` dosyasında `DATABASE_URL` boş — Adım 3'e dönün |
| "JWT_SECRET ortam değişkeni tanımlı değil" | `.env` dosyasında `JWT_SECRET` boş |
| Bağlantı zaman aşımına uğruyor | Supabase projenizin "pause" (uykuda) durumda olmadığından emin olun (ücretsiz katmanda uzun süre kullanılmayan projeler duraklatılır); Dashboard'dan uyandırın |
| "self signed certificate" hatası | `.env`'de `DATABASE_SSL_STRICT=false` olduğundan emin olun (varsayılan zaten budur) |
| Giriş "Hatalı şifre" veriyor | `seed.js` çıktısındaki şifreyi doğru kopyaladığınızdan emin olun |

---

## Sırada Ne Var?

Uygulamayı Vercel'e deploy etmek isterseniz `DEPLOY_REHBERI.md` dosyasına bakın — Supabase +
Vercel kombinasyonuna özel adımlar orada güncellendi.
