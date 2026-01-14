# 🔧 OAuth State Error Troubleshooting

## Error: "Invalid or expired state"

### Gejala

```
[AUTH_OAUTH_CALLBACK] ERROR: Invalid or expired state: 'bEHczO9M...'
400 | /api/auth/google/callback
```

---

## Penyebab & Solusi

### 1. **Server Restart Saat OAuth Flow** ⚠️ MOST COMMON

**Problem**: Klik login Google → Server restart → Redirect callback → State hilang

**Penjelasan**:

- State disimpan **di memory** (in-memory map)
- Ketika server restart, semua state hilang
- OAuth callback datang dengan state yang sudah tidak ada di memory

**Solusi Development**:

```bash
# Jangan restart server saat ada OAuth flow yang sedang berjalan!
# Kalau server restart, klik login Google lagi dari awal
```

**Solusi Production**: Gunakan Redis atau database untuk menyimpan state (opsional)

---

### 2. **OAuth Flow Terlalu Lama** ⏱️

**Problem**: User klik login Google, tapi baru selesai authorize setelah 15+ menit

**Setting Sekarang**:

- State TTL: **15 menit** (sudah cukup)
- Jika lebih dari 15 menit, state expired

**Solusi**:

```bash
# Tidak perlu action - 15 menit sudah sangat cukup
# Kalau user memang lama di halaman Google, suruh login ulang
```

---

### 3. **Multiple Server Instances** 🖥️

**Problem**: Load balancer/multiple backend instances

**Penjelasan**:

- User login di server A → state tersimpan di memory server A
- Callback ke server B → state tidak ada di memory server B

**Solusi**: Gunakan Redis untuk shared state storage (production setup)

---

### 4. **State Parameter Corrupt/Missing**

**Problem**: URL callback tidak memiliki parameter `state`

**Check**:

```bash
# URL callback harus seperti ini:
https://your-backend.com/api/auth/google/callback?code=XXX&state=YYY

# Jika tidak ada state parameter, masalah ada di Google OAuth config
```

---

## Debug dengan Log Baru

Sekarang ada debug logging yang lebih detail:

### Saat Login (Store State)

```
[AUTH_OAUTH_LOGIN] Redirecting to Google OAuth (state=bEHczO9M...)
[OAUTH_STATE_DEBUG] Stored state: bEHczO9M... (expires in 15m0s, total_states=1)
```

### Saat Callback (Validate State)

```
[OAUTH_STATE_DEBUG] Validating state: bEHczO9M... (found=true, total_states=1)
[OAUTH_STATE_DEBUG] State valid (age=2s)
```

### Jika State Error

```
[OAUTH_STATE_DEBUG] Validating state: bEHczO9M... (found=false, total_states=0)
[AUTH_OAUTH_CALLBACK] ERROR: State validation failed: state not found (already used, server restarted, or never created)
```

**Error messages sekarang**:

- ✅ `state not found (already used, server restarted, or never created)`
- ✅ `state expired (age=20m, ttl=15m)`
- ✅ Response JSON berisi `details` field untuk debugging

---

## Testing Flow

### Test 1: Happy Path (Normal Flow)

```bash
# 1. Start backend (jangan restart!)
cd backend
go run cmd/server/main.go

# 2. Buka browser
http://localhost:3000

# 3. Klik "Login with Google"
# Expected logs:
[AUTH_OAUTH_LOGIN] Redirecting to Google OAuth (state=xxx...)
[OAUTH_STATE_DEBUG] Stored state: xxx... (expires in 15m0s)

# 4. Login di Google (jangan lebih dari 15 menit!)
# Expected logs:
[OAUTH_STATE_DEBUG] Validating state: xxx... (found=true)
[OAUTH_STATE_DEBUG] State valid (age=2s)
[AUTH_OAUTH_CALLBACK_TIMING] google_exchange=320ms
```

### Test 2: Server Restart (Error Case)

```bash
# 1. Klik "Login with Google"
[OAUTH_STATE_DEBUG] Stored state: xxx...

# 2. RESTART BACKEND SEKARANG
# Ctrl+C dan go run cmd/server/main.go lagi

# 3. Finish login di Google
# Expected error:
[OAUTH_STATE_DEBUG] Validating state: xxx... (found=false, total_states=0)
ERROR: state not found (already used, server restarted, or never created)

# Solution: Klik "Login with Google" lagi dari awal
```

### Test 3: State Expired (Edge Case)

```bash
# 1. Klik "Login with Google"
[OAUTH_STATE_DEBUG] Stored state: xxx... (expires in 15m0s)

# 2. Tunggu 16 menit (jangan login di Google)

# 3. Sekarang login di Google
# Expected error:
ERROR: state expired (age=16m, ttl=15m)

# Solution: Klik "Login with Google" lagi
```

---

## Perubahan yang Sudah Dibuat

### 1. State TTL: 10min → 15min

```go
// File: auth_handler.go
var oauthStateStore = newInMemoryOAuthStateStore(15 * time.Minute) // was 10
```

### 2. Debug Logging

```go
// Sekarang ada log untuk:
- State creation (store)
- State validation (consume)
- State age & TTL
- Total active states
- Detailed error messages
```

### 3. Better Error Messages

```json
// Sebelum
{"error": "Invalid or expired state parameter"}

// Sekarang
{
  "error": "Invalid or expired state parameter",
  "details": "state not found (already used, server restarted, or never created)"
}
```

---

## Checklist untuk User

Jika dapat error state:

- [ ] **Check backend logs** untuk `[OAUTH_STATE_DEBUG]`
- [ ] **Apakah server restart** saat OAuth flow?
- [ ] **Berapa lama** dari klik login sampai callback? (max 15 menit)
- [ ] **Login ulang** dari awal (klik "Login with Google" lagi)
- [ ] **Check environment**:
  ```bash
  APP_ENV=development
  AUTH_COOKIE_DEBUG=true
  GOOGLE_REDIRECT_URL=<your-ngrok-url>/api/auth/google/callback
  FRONTEND_URL=http://localhost:3000
  ```

---

## Environment Variables Penting

```bash
# Backend .env
APP_ENV=development
AUTH_COOKIE_DEBUG=true

# OAuth URLs - HARUS match dengan Google Console
GOOGLE_REDIRECT_URL=https://866f002ff95f.ngrok-free.app/api/auth/google/callback
FRONTEND_URL=http://localhost:3000

# Google Credentials
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxx
```

### Update Google Console

Pastikan Google OAuth Redirect URI match dengan `GOOGLE_REDIRECT_URL`:

**Google Cloud Console** → APIs & Services → Credentials → OAuth 2.0 Client IDs:

```
Authorized redirect URIs:
✅ https://866f002ff95f.ngrok-free.app/api/auth/google/callback
✅ http://localhost:5000/api/auth/google/callback (untuk dev)
```

---

## Production Considerations

Untuk production, pertimbangkan:

### Option 1: Redis-backed State Store

```go
// Gunakan Redis untuk shared state antar server instances
type redisOAuthStateStore struct {
    client *redis.Client
    ttl    time.Duration
}
```

### Option 2: Stateless JWT State

```go
// Encode state di JWT, verify signature saat callback
// Tidak perlu simpan di server
```

### Option 3: Database-backed State

```go
// Simpan di MySQL/PostgreSQL dengan TTL
type OAuthState struct {
    State     string
    CreatedAt time.Time
    ExpiresAt time.Time
}
```

---

## Quick Fix Summary

**Jika error state terjadi sekarang**:

1. ✅ **Restart backend** (clear semua state lama)
2. ✅ **Klik "Login with Google"** lagi dari awal
3. ✅ **Jangan restart backend** saat ada OAuth flow
4. ✅ **Selesaikan OAuth dalam 15 menit**

**Logs yang harus ada**:

```
[AUTH_OAUTH_LOGIN] Redirecting to Google OAuth (state=xxx...)
[OAUTH_STATE_DEBUG] Stored state: xxx... (expires in 15m0s)
... (user login di Google) ...
[OAUTH_STATE_DEBUG] Validating state: xxx... (found=true)
[OAUTH_STATE_DEBUG] State valid (age=2s)
[AUTH_OAUTH_CALLBACK_TIMING] google_exchange=320ms
```

Jika tidak ada log `[OAUTH_STATE_DEBUG]`, pastikan:

```bash
APP_ENV=development
AUTH_COOKIE_DEBUG=true
```

---

## Related Files

- State Management: [auth_handler.go](backend/internal/handler/auth_handler.go#L176-L225)
- OAuth Flow: [auth_handler.go](backend/internal/handler/auth_handler.go#L265-L355)
- Environment: [.env](backend/.env)

---

**TL;DR**: State hilang karena server restart. Jangan restart backend saat OAuth flow sedang berjalan. Kalau udah telanjur error, login ulang dari awal.
