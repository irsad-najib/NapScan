# 🚀 Development Setup - Cookie Auth dengan Ngrok

## Quick Start untuk Development

### 1. Setup Backend

```bash
cd backend

# Install dependencies
go mod download

# Copy .env (sudah ada di project)
# Pastikan APP_ENV=development

# Run backend
go run cmd/server/main.go
```

### 2. Setup Ngrok (Optional)

```bash
# Install ngrok: https://ngrok.com/download
# Login: ngrok config add-authtoken <your-token>

# Expose backend ke internet
ngrok http 5000
```

Ngrok akan memberikan URL seperti: `https://abc123.ngrok-free.app`

### 3. Update Backend URLs

Edit `backend/.env`:

```bash
# Ganti dengan ngrok URL yang baru
GOOGLE_REDIRECT_URL=https://abc123.ngrok-free.app/api/auth/google/callback
AUTH_SUCCESS_REDIRECT_URL=https://abc123.ngrok-free.app
```

### 4. Setup Frontend

```bash
cd frontend

# Install dependencies
npm install

# Update .env dengan ngrok URL
echo "NEXT_PUBLIC_API_URL=https://abc123.ngrok-free.app" > .env.local

# Run frontend
npm run dev
```

---

## ✨ Fitur Auto-CORS untuk Development

**Tidak perlu update CORS_ALLOW_ORIGINS setiap kali ngrok restart!**

Dalam mode `APP_ENV=development`, backend **otomatis menerima** request dari:

- ✅ `http://localhost:*` (semua port)
- ✅ `https://localhost:*`
- ✅ `*.ngrok-free.app` (semua ngrok URLs)
- ✅ `*.ngrok.io`
- ✅ `*.ngrok.app`
- ✅ `http://127.0.0.1:*`

**Kode yang bertanggung jawab**: [cors.go](backend/internal/middleware/cors.go#L24-L54)

---

## 🍪 Cookie Configuration untuk Development

### Backend `.env` minimal:

```bash
APP_ENV=development

# Cookie settings - otomatis menyesuaikan dengan cross-site
AUTH_COOKIE_DEBUG=true
AUTH_COOKIE_SAMESITE=none
AUTH_COOKIE_SECURE=true

# CORS - localhost otomatis diizinkan dalam dev mode
CORS_ALLOW_ORIGINS=http://localhost:3000
```

### Frontend `.env.local`:

```bash
# Gunakan ngrok URL atau localhost
NEXT_PUBLIC_API_URL=https://abc123.ngrok-free.app

# Enable credentials (default: true, tidak perlu set)
# NEXT_PUBLIC_WITH_CREDENTIALS=true
```

---

## 🔄 Workflow: Ngrok URL Berubah

Ketika ngrok di-restart dan URL berubah:

### ❌ Cara Lama (Ribet):

1. Update `CORS_ALLOW_ORIGINS` di backend
2. Update `GOOGLE_REDIRECT_URL` di backend
3. Update `AUTH_SUCCESS_REDIRECT_URL` di backend
4. Update `NEXT_PUBLIC_API_URL` di frontend
5. Restart backend
6. Restart frontend

### ✅ Cara Baru (Mudah):

1. Update `GOOGLE_REDIRECT_URL` di backend
2. Update `AUTH_SUCCESS_REDIRECT_URL` di backend (opsional)
3. Update `NEXT_PUBLIC_API_URL` di frontend
4. **CORS otomatis menerima ngrok URL baru!** 🎉

---

## 🐛 Debug Cookie Issues

### 1. Enable Debug Logs

```bash
# Backend .env
AUTH_COOKIE_DEBUG=true
```

### 2. Check Browser DevTools

**Chrome**: F12 → Network tab

- Lihat request ke `/api/auth/me`
- Check **Request Headers** → harus ada `Cookie: napscan_access_token=...`

**Chrome**: F12 → Application → Cookies

- Domain: `https://your-ngrok.ngrok-free.app`
- Cookie: `napscan_access_token`
- HttpOnly: ✓
- Secure: ✓
- SameSite: None

### 3. Check Backend Logs

Cari output seperti:

```
[AUTH_COOKIE_DEBUG] set-cookie (proto="https" ...) "napscan_access_token=<redacted>; ..."
[AUTH_COOKIE_DEBUG] incoming GET /api/auth/me ... cookie_present=true
```

---

## ⚡ Tips Performance

### Masalah: "Set cookie lama"

Biasanya bukan masalah cookie, tapi:

1. **Network latency**: Ngrok menambah ~100-300ms latency
2. **Cold start**: First request bisa lambat (database connection)
3. **OAuth redirect**: Google OAuth punya 2-3 redirect chains

### Solusi:

```bash
# 1. Gunakan localhost untuk development cepat (tanpa ngrok)
NEXT_PUBLIC_API_URL=http://localhost:5000

# 2. Atau gunakan ngrok hanya untuk testing OAuth
# (Request lain tetap ke localhost)
```

### Benchmark Typical Latency:

- **Localhost → Localhost**: ~10-50ms
- **Localhost → Ngrok → Localhost**: ~150-400ms
- **OAuth Flow (Google)**: ~1-3 detik (normal)

---

## 📊 Mode Development vs Production

### Development (APP_ENV=development)

✅ CORS auto-accept localhost + ngrok  
✅ Cookie debug logs enabled  
✅ Detailed error messages  
✅ SameSite=None untuk cross-site testing  
⚠️ **JANGAN deploy ke production!**

### Production (APP_ENV=production)

❌ CORS strict (hanya domain yang di-whitelist)  
❌ No debug logs  
❌ Generic error messages  
✅ SameSite=Lax atau Strict  
✅ Secure cookies only (HTTPS)

---

## 🔒 Keamanan Development

**Aman untuk development karena**:

- CORS permisif **HANYA** aktif jika `APP_ENV=development`
- Production tetap strict (check kode di [cors.go](backend/internal/middleware/cors.go#L26))
- Cookie tetap HttpOnly (tidak bisa diakses JavaScript)

**Sebelum deploy production**:

```bash
# Backend .env
APP_ENV=production
CORS_ALLOW_ORIGINS=https://your-production-domain.com
AUTH_COOKIE_DEBUG=false
AUTH_COOKIE_SAMESITE=lax
```

---

## 📱 Testing di Mobile Device

Jika ingin test di HP menggunakan ngrok:

1. Start ngrok: `ngrok http 5000`
2. Update frontend `.env.local` dengan ngrok URL
3. Akses frontend di HP: `http://localhost:3000`
4. Frontend akan call backend via ngrok (HTTPS)
5. **Cookie otomatis work** karena ngrok sudah HTTPS

---

## 🆘 Troubleshooting

### Cookie tidak ter-set

```bash
# Check backend logs
[AUTH_COOKIE_DEBUG] set-cookie ...

# Jika tidak ada output: Login endpoint tidak dipanggil
# Jika ada tapi cookie hilang: Check SameSite/Secure flags
```

### CORS error

```bash
# Check browser console:
Access-Control-Allow-Origin: ...

# Jika error: Pastikan APP_ENV=development
# Check backend logs untuk melihat origin yang ditolak
```

### 401 Unauthorized

```bash
# Check request headers (DevTools → Network):
Cookie: napscan_access_token=...

# Jika tidak ada cookie: Browser blocked (check SameSite)
# Jika ada cookie: JWT mungkin expired atau invalid
```

---

## 📚 Files Terkait

- **CORS Config**: [backend/internal/middleware/cors.go](backend/internal/middleware/cors.go)
- **Cookie Logic**: [backend/internal/handler/auth_handler.go](backend/internal/handler/auth_handler.go)
- **Frontend API**: [frontend/src/services/api/http.ts](frontend/src/services/api/http.ts)
- **Debug Guide**: [COOKIE_AUTH_DEBUG.md](COOKIE_AUTH_DEBUG.md)

---

Selamat coding! 🚀
