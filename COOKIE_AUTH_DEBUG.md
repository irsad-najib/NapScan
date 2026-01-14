# 🍪 Cookie-Based Authentication Debugging Guide

## Issue: Cookies Not Being Sent Back to Backend

### Symptoms

- ✅ Login succeeds (201/200 response)
- ✅ Cookie visible in Chrome DevTools → Application → Cookies
- ❌ Subsequent requests return 401 Unauthorized
- ❌ Backend logs show cookie is missing/empty

---

## Root Causes & Solutions

### 1. **CORS Origin Mismatch** ⚠️ MOST COMMON

**Problem**: Backend CORS only allows `http://localhost:3000`, but frontend uses ngrok (`https://xxx.ngrok-free.app`)

**Solution**: Update backend `.env`

```bash
# Allow BOTH localhost and ngrok (comma-separated)
CORS_ALLOW_ORIGINS=http://localhost:3000,https://866f002ff95f.ngrok-free.app
```

**Why**: Browsers reject cookies when the Origin header doesn't match CORS allowed origins.

---

### 2. **SameSite Policy for Cross-Site Requests**

**Problem**: Cross-site requests (localhost → ngrok or different domains) require special cookie flags

**Solution**: Update backend `.env`

```bash
AUTH_COOKIE_SAMESITE=none
AUTH_COOKIE_SECURE=true
```

**Why**:

- `SameSite=None` allows cross-site cookie transmission
- `Secure=true` is mandatory when using `SameSite=None` (requires HTTPS)
- Your code in `auth_handler.go` auto-detects this, but env vars override it

**Reference**: [auth_handler.go](backend/internal/handler/auth_handler.go#L125-L134)

---

### 3. **Frontend Must Use `withCredentials: true`** ✅ Already Fixed

**Status**: Your code already has this configured correctly!

```typescript
// frontend/src/services/api/http.ts
export const api: AxiosInstance = axios.create({
  withCredentials: DEFAULT_WITH_CREDENTIALS, // ✅ Defaults to true
});
```

---

### 4. **CORS Must Allow Credentials** ✅ Already Fixed

**Status**: Your code already has this configured correctly!

```go
// backend/internal/middleware/cors.go
return cors.New(cors.Config{
  AllowCredentials: true, // ✅ Correct
});
```

**Critical**: NEVER use `AllowOrigins: "*"` with `AllowCredentials: true`. This is forbidden by browsers.

---

## Chrome DevTools Debug Checklist

### Step 1: Verify Cookie Is Set After Login

1. Open DevTools → **Application** tab → **Cookies** → Select your domain
2. Find cookie named: `napscan_access_token`
3. Check attributes:
   - ✅ **HttpOnly**: true (JavaScript can't read it)
   - ✅ **Secure**: true (required for HTTPS/ngrok)
   - ✅ **SameSite**: None (for cross-site) OR Lax (same-site)
   - ✅ **Domain**: Should match your backend domain
   - ✅ **Path**: `/`

### Step 2: Verify Cookie Is Sent on Subsequent Requests

1. Open DevTools → **Network** tab
2. Trigger a request to `/api/auth/me` or any protected endpoint
3. Click the request → **Headers** tab
4. Check **Request Headers** section:
   - ✅ Look for: `Cookie: napscan_access_token=<token>`

**If missing**: Browser is blocking the cookie. Check CORS/SameSite settings.

### Step 3: Check for CORS Errors

1. In **Network** tab, look for:
   - ❌ Red requests with `(failed)` or `net::ERR_FAILED`
   - ❌ Status `0` or empty response
2. Check **Console** tab for:
   - ❌ `Access-Control-Allow-Origin` errors
   - ❌ `Access-Control-Allow-Credentials` errors

### Step 4: Inspect Preflight Requests (OPTIONS)

1. Filter Network tab by: `OPTIONS`
2. For each OPTIONS request to your backend:
   - ✅ Status should be `204` or `200`
   - ✅ Response headers must include:
     ```
     Access-Control-Allow-Origin: <your-frontend-origin>
     Access-Control-Allow-Credentials: true
     Access-Control-Allow-Headers: Origin, Content-Type, Accept, Authorization
     ```

### Step 5: Backend Debug Logs

Enable cookie debugging in backend `.env`:

```bash
AUTH_COOKIE_DEBUG=true
```

Then check backend logs for:

```
[AUTH_COOKIE_DEBUG] set-cookie (proto="https" ...) "napscan_access_token=<redacted>; ..."
[AUTH_COOKIE_DEBUG] incoming GET /api/auth/me origin="https://..." cookie_present=true
[AUTH_ME_DEBUG] cookie_present=true cookie_len=XXX
```

**If `cookie_present=false`**: Cookie is not being sent by browser.

---

## Quick Test Procedure

### Test 1: Same-Site (Localhost Only)

```bash
# Backend
cd backend
export CORS_ALLOW_ORIGINS=http://localhost:3000
export AUTH_COOKIE_SAMESITE=lax
export AUTH_COOKIE_SECURE=false
go run cmd/server/main.go

# Frontend
cd frontend
export NEXT_PUBLIC_API_URL=http://localhost:5000
npm run dev
```

**Expected**: Cookies work when accessing `http://localhost:3000`

---

### Test 2: Cross-Site (Ngrok)

```bash
# Backend
cd backend
export CORS_ALLOW_ORIGINS=http://localhost:3000,https://866f002ff95f.ngrok-free.app
export AUTH_COOKIE_SAMESITE=none
export AUTH_COOKIE_SECURE=true
go run cmd/server/main.go

# Start ngrok
ngrok http 5000

# Frontend (update .env with ngrok URL)
cd frontend
export NEXT_PUBLIC_API_URL=https://866f002ff95f.ngrok-free.app
npm run dev
```

**Expected**: Cookies work when accessing `http://localhost:3000` → ngrok backend

---

## Common Mistakes

### ❌ Using `CORS_ALLOW_ORIGINS=*`

```go
AllowOrigins: "*",           // ❌ WRONG
AllowCredentials: true,      // ❌ Browsers reject this combo
```

### ✅ Correct: Explicit Origins

```go
AllowOrigins: "http://localhost:3000,https://xxx.ngrok-free.app",  // ✅ Specific
AllowCredentials: true,                                              // ✅ Works
```

---

### ❌ Forgetting `withCredentials: true` on Frontend

```typescript
// ❌ WRONG: Cookies won't be sent
fetch("/api/auth/me", {
  // missing credentials: 'include'
});

// ✅ CORRECT
fetch("/api/auth/me", {
  credentials: "include", // ✅ Send cookies
});

// OR with axios
axios.get("/api/auth/me", {
  withCredentials: true, // ✅ Send cookies
});
```

---

### ❌ Using `SameSite=None` Without `Secure=true`

```go
cookie := &fiber.Cookie{
  SameSite: "None",   // ❌ Requires Secure
  Secure:   false,    // ❌ Browser rejects cookie
}
```

Modern browsers **silently ignore** cookies with `SameSite=None; Secure=false`.

---

## Environment Variables Reference

### Backend `.env`

```bash
# CORS - MUST include frontend origin
CORS_ALLOW_ORIGINS=http://localhost:3000,https://xxx.ngrok-free.app

# Cookie Settings
AUTH_COOKIE_NAME=napscan_access_token
AUTH_COOKIE_SAMESITE=none     # none|lax|strict (use 'none' for cross-site)
AUTH_COOKIE_SECURE=true       # true for HTTPS (ngrok), false for HTTP (localhost)
AUTH_COOKIE_DEBUG=true        # Enable debug logs

# OAuth Redirect
GOOGLE_REDIRECT_URL=https://xxx.ngrok-free.app/api/auth/google/callback
AUTH_SUCCESS_REDIRECT_URL=https://xxx.ngrok-free.app

# Development
APP_ENV=development
```

### Frontend `.env`

```bash
# Backend URL (must match CORS_ALLOW_ORIGINS)
NEXT_PUBLIC_API_URL=https://866f002ff95f.ngrok-free.app

# Enable credentials (cookie sending)
NEXT_PUBLIC_WITH_CREDENTIALS=true
```

---

## Advanced: Debugging with cURL

### Test Cookie Setting

```bash
# Login and capture Set-Cookie header
curl -i -X POST https://866f002ff95f.ngrok-free.app/api/auth/google \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3000" \
  -d '{"id_token": "..."}'

# Look for Set-Cookie in response:
# Set-Cookie: napscan_access_token=...; HttpOnly; Secure; SameSite=None; Path=/
```

### Test Cookie Reading

```bash
# Send cookie manually
curl -X GET https://866f002ff95f.ngrok-free.app/api/auth/me \
  -H "Cookie: napscan_access_token=<token-from-login>" \
  -H "Origin: http://localhost:3000"

# Should return 200 with user data
```

---

## Production Checklist

Before deploying to production:

- [ ] Set `APP_ENV=production` in backend
- [ ] Set `NODE_ENV=production` in backend
- [ ] Use real domain in `CORS_ALLOW_ORIGINS` (no localhost)
- [ ] Set `AUTH_COOKIE_SECURE=true` (HTTPS only)
- [ ] Set `AUTH_COOKIE_SAMESITE=lax` (or `strict` if same-domain)
- [ ] Disable `AUTH_COOKIE_DEBUG=false`
- [ ] Use strong `JWT_SECRET` (not dev default)
- [ ] Update `GOOGLE_REDIRECT_URL` to production domain
- [ ] Update `AUTH_SUCCESS_REDIRECT_URL` to production frontend

---

## References

- [MDN: HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [MDN: SameSite Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [Chrome: SameSite Cookie Updates](https://www.chromium.org/updates/same-site)
- [Fiber Cookie Docs](https://docs.gofiber.io/api/ctx#cookie)
- Your code: [auth_handler.go](backend/internal/handler/auth_handler.go)
