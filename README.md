# Go + PostgreSQL Auth API

Go (Gin framework) ve PostgreSQL ile yazılmış, JWT tabanlı bir kullanıcı yönetimi API'si. Mini öğrenme projesi.

## Özellikler

- Kullanıcı kaydı (bcrypt hashleme ile)
- Email + şifre ile login → JWT token
- Misafir (guest) erişimi
- Token doğrulama middleware'i
- Şifre değiştirme (eski şifre kontrolü)
- Kullanıcı adı değiştirme (unique kontrol)
- Şifre sıfırlama akışı (forgot + reset)
- Net Türkçe hata mesajları

## Klasör Yapısı

```
auth-api/
├── config/         # .env okuma
├── database/       # PostgreSQL bağlantısı + migration
├── handlers/       # HTTP handler'ları
├── middleware/     # JWT auth middleware
├── models/         # User struct ve request DTO'lar
├── routes/         # Route tanımları
├── utils/          # JWT, bcrypt, response helper
├── main.go
├── go.mod
└── .env.example
```

## Kurulum

### 1. PostgreSQL'i hazırla

```bash
# Docker ile en hızlı yol:
docker run --name auth-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=authdb \
  -p 5432:5432 \
  -d postgres:16
```

Yerelde kuruluysa:

```sql
CREATE DATABASE authdb;
```

### 2. .env dosyasını oluştur

```bash
cp .env.example .env
# JWT_SECRET'i değiştirmeyi unutma!
```

### 3. Bağımlılıkları yükle ve çalıştır

```bash
go mod tidy
go run main.go
```

Sunucu varsayılan olarak `http://localhost:8080` adresinde çalışır.

## Endpoint'ler

### Public (token gerektirmez)

| Method | Path                          | Açıklama                       |
|--------|-------------------------------|--------------------------------|
| POST   | `/api/v1/auth/register`       | Yeni kullanıcı kaydı           |
| POST   | `/api/v1/auth/login`          | Giriş yap, token al            |
| POST   | `/api/v1/auth/guest`          | Misafir token al               |
| POST   | `/api/v1/auth/forgot-password`| Şifre sıfırlama tokenı talep et|
| POST   | `/api/v1/auth/reset-password` | Token ile şifreyi sıfırla      |

### Private (Authorization: Bearer <token> gerekir)

| Method | Path                            | Açıklama                |
|--------|---------------------------------|-------------------------|
| GET    | `/api/v1/user/me`               | Kendi bilgilerini gör   |
| PUT    | `/api/v1/user/change-password`  | Şifre değiştir          |
| PUT    | `/api/v1/user/change-username`  | Kullanıcı adı değiştir  |

## Test (Postman)

Projedeki `postman_collection.json` dosyasını Postman'e import et. Koleksiyon değişken olarak `base_url` ve `token` saklar; Login endpoint'ini çağırdığında token otomatik kaydedilir.

## Hata Yönetimi

Tüm hatalar şu formatta döner:

```json
{
  "success": false,
  "error": "Bu kullanıcı adı zaten alınmış"
}
```

Yönetilen senaryolar:
- "Eski şifre yanlış, yeni şifreyle eşleşmiyor"
- "Bu kullanıcı adı zaten alınmış"
- "Bu email zaten kayıtlı"
- "Geçersiz veya süresi dolmuş token"
- "Email veya şifre hatalı"
- "Reset tokenının süresi dolmuş"
- "Misafir kullanıcılar bu işlemi yapamaz"

## Notlar

- Reset token gerçek bir uygulamada email ile gönderilir. Bu projede öğrenme amaçlı response içinde dönülüyor.
- JWT süresi varsayılan 24 saat (env'den ayarlanabilir).
- Misafir token süresi 1 saat.
