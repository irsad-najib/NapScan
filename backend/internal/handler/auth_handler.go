package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

const (
	defaultAuthCookieName  = "napscan_access_token"
	defaultOAuthStateCookie = "napscan_oauth_state"
)

func authCookieName() string {
	if v := strings.TrimSpace(os.Getenv("AUTH_COOKIE_NAME")); v != "" {
		return v
	}
	return defaultAuthCookieName
}

func isSecureCookie() bool {
	// Fiber won't set Secure cookies over plain HTTP, so keep dev-friendly defaults.
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_COOKIE_SECURE"))); v == "1" || v == "true" || v == "yes" {
		return true
	}
	return strings.ToLower(strings.TrimSpace(os.Getenv("NODE_ENV"))) == "production"
}

func sameSiteMode() string {
	// Default is Lax: works with OAuth redirect flows and helps mitigate CSRF.
	// Use None only if your frontend is truly cross-site and you can serve HTTPS.
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_COOKIE_SAMESITE"))); v != "" {
		switch v {
		case "lax", "strict", "none":
			return strings.Title(v)
		}
	}
	return "Lax"
}

func shouldUseCrossSiteCookie(c *fiber.Ctx) bool {
	// When frontend and backend are on different sites (e.g. localhost -> ngrok / prod domains),
	// browsers will NOT send cookies on XHR/fetch unless SameSite=None; Secure.
	// We detect this via Origin vs Host comparison.
	origin := strings.TrimSpace(c.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := strings.TrimSpace(u.Hostname())
	if originHost == "" {
		return false
	}
	return !strings.EqualFold(originHost, c.Hostname())
}

func isExternalHTTPS(c *fiber.Ctx) bool {
	// When running behind a reverse proxy (e.g. ngrok), Fiber may see the request as HTTP
	// even though the browser connects via HTTPS. Use forwarded headers to detect this.
	if strings.EqualFold(c.Protocol(), "https") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(c.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(c.Get("X-Forwarded-Ssl")), "on") {
		return true
	}
	return false
}

func redactSetCookieValue(setCookie, cookieName string) string {
	needle := cookieName + "="
	for {
		i := strings.Index(setCookie, needle)
		if i == -1 {
			return setCookie
		}
		start := i + len(needle)
		end := strings.Index(setCookie[start:], ";")
		if end == -1 {
			return setCookie[:start] + "<redacted>"
		}
		end = start + end
		setCookie = setCookie[:start] + "<redacted>" + setCookie[end:]
	}
}

func (h *AuthHandler) setAuthCookie(c *fiber.Ctx, jwtToken string) {
	// Fast path: simple cookie creation without complex checks
	cookie := &fiber.Cookie{
		Name:     authCookieName(),
		Value:    jwtToken,
		HTTPOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		// Always use None + Secure for development (ngrok compatibility)
		SameSite: "None",
		Secure:   true,
	}
	
	// Set cookie IMMEDIATELY - this is the critical path
	c.Cookie(cookie)
	
	// Anti-cache headers
	c.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	c.Set("Pragma", "no-cache")
	c.Set("Expires", "0")
}

func (h *AuthHandler) clearAuthCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     authCookieName(),
		Value:    "",
		HTTPOnly: true,
		Secure:   isSecureCookie(),
		SameSite: sameSiteMode(),
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func randomStateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// oauthStateStore keeps OAuth state server-side to avoid relying on browser cookies.
// This makes the flow robust across localhost/ngrok/cross-domain redirects where
// SameSite/Secure/Domain cookie rules may prevent the state cookie from being sent.
var oauthStateStore = newInMemoryOAuthStateStore(15 * time.Minute)

type inMemoryOAuthStateStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]time.Time
}

func newInMemoryOAuthStateStore(ttl time.Duration) *inMemoryOAuthStateStore {
	return &inMemoryOAuthStateStore{ttl: ttl, m: make(map[string]time.Time)}
}

func (s *inMemoryOAuthStateStore) Put(state string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Opportunistic cleanup to avoid unbounded growth if users abandon the flow.
	if len(s.m) > 2048 {
		cutoff := now.Add(-s.ttl)
		for k, ts := range s.m {
			if ts.Before(cutoff) {
				delete(s.m, k)
			}
		}
	}

	s.m[state] = now
	
	if os.Getenv("APP_ENV") == "development" && strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_COOKIE_DEBUG"))) == "true" {
		log.Printf("[OAUTH_STATE_DEBUG] Stored state: %s (expires in %v, total_states=%d)", state[:16]+"...", s.ttl, len(s.m))
	}
}

// Consume validates state and makes it single-use by deleting it.
func (s *inMemoryOAuthStateStore) Consume(state string) (bool, string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, ok := s.m[state]
	delete(s.m, state) // single-use regardless of validity
	
	if os.Getenv("APP_ENV") == "development" && strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_COOKIE_DEBUG"))) == "true" {
		log.Printf("[OAUTH_STATE_DEBUG] Validating state: %s (found=%v, total_states=%d)", state[:16]+"...", ok, len(s.m))
	}
	
	if !ok {
		return false, "state not found (already used, server restarted, or never created)"
	}
	
	age := now.Sub(ts)
	if age > s.ttl {
		return false, fmt.Sprintf("state expired (age=%v, ttl=%v)", age.Round(time.Second), s.ttl)
	}
	
	if os.Getenv("APP_ENV") == "development" && strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_COOKIE_DEBUG"))) == "true" {
		log.Printf("[OAUTH_STATE_DEBUG] State valid (age=%v)", age.Round(time.Second))
	}
	
	return true, ""
}

// GoogleLogin (POST) handles the ID Token flow (SPA/Mobile)
// @Summary Google OAuth Login (ID Token)
// @Description Validates Google ID token sent from Frontend and issues JWT
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.GoogleAuthRequest true "Google Auth Request"
// @Success 200 {object} models.AuthResponse
// @Router /auth/google [post]
func (h *AuthHandler) GoogleLogin(c *fiber.Ctx) error {
	var req models.GoogleAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.IDToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id_token is required"})
	}

	// Verify Google Token
	user, err := h.authService.VerifyGoogleToken(c.Context(), req.IDToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid Google token: " + err.Error()})
	}

	// Generate JWT
	token, err := h.authService.GenerateJWT(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate session"})
	}

	h.setAuthCookie(c, token)

	// UBAH DISINI: Kembalikan token agar frontend bisa menyimpannya di localStorage
	return c.JSON(models.AuthResponse{
		AccessToken: token, // DULU: "", SEKARANG: token
		User:        *user,
	})
}

// GoogleLoginRedirect (GET) initiates the Server-Side Flow
// @Summary Google Login Redirect
// @Description Redirects user to Google Login Page (Server-Side Flow)
// @Tags Auth
// @Success 302
// @Router /auth/google/login [get]
func (h *AuthHandler) GoogleLoginRedirect(c *fiber.Ctx) error {
	state, err := randomStateToken()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate oauth state"})
	}

	// Store state on the server (not in cookies) so cross-domain redirects (ngrok/prod)
	// don't break due to SameSite/Secure/Domain cookie restrictions.
	oauthStateStore.Put(state)

	url := h.authService.GetGoogleLoginURL(state)
	log.Printf("[AUTH_OAUTH_LOGIN] Redirecting to Google OAuth (state=%s...)", state[:16])
	return c.Redirect(url)
}

// GoogleCallback (GET) handles the return from Google
// @Summary Google OAuth Callback
// @Description Exchanges Auth Code for Token, creates User session, returns JWT
// @Tags Auth
// @Param code query string true "Auth Code"
// @Param state query string false "State"
// @Success 200 {object} models.AuthResponse
// @Router /auth/google/callback [get]
func (h *AuthHandler) GoogleCallback(c *fiber.Ctx) error {
	log.Println("[AUTH_OAUTH_CALLBACK] Handling Google callback")
	overallStart := time.Now()
	stepStart := time.Now()
	
	// Skip CORS for this endpoint - it's a browser redirect from Google, not an XHR
	// This prevents OPTIONS preflight delays
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Credentials", "true")

	state := c.Query("state")
	valid, errMsg := oauthStateStore.Consume(state)
	if !valid {
		log.Printf("[AUTH_OAUTH_CALLBACK] ERROR: State validation failed: %s (state=%s)", errMsg, state[:16]+"...")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid or expired state parameter",
			"details": errMsg,
		})
	}
	log.Printf("[AUTH_OAUTH_CALLBACK_TIMING] state_validation=%s", time.Since(stepStart))
	stepStart = time.Now() // Reset timer for next step

	code := c.Query("code")
	if code == "" {
		log.Println("[AUTH_OAUTH_CALLBACK] ERROR: Missing code parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing authorization code"})
	}

	// Exchange authorization code for token and get user info
	log.Printf("[AUTH_OAUTH_CALLBACK] Starting Google token exchange...")
	user, err := h.authService.HandleGoogleCallback(c.Context(), code)
	if err != nil {
		log.Printf("[AUTH_OAUTH_CALLBACK] ERROR: Failed during code exchange: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to authenticate with Google",
			"details": err.Error(),
		})
	}
	exchangeDuration := time.Since(stepStart)
	log.Printf("[AUTH_OAUTH_CALLBACK_TIMING] google_exchange=%s", exchangeDuration)
	if exchangeDuration > 5*time.Second {
		log.Printf("[AUTH_OAUTH_CALLBACK] ⚠️  WARNING: Google exchange took longer than 5s: %s", exchangeDuration)
	}
	stepStart = time.Now() // Reset timer for next step

	// Generate JWT token
	jwtToken, err := h.authService.GenerateJWT(user)
	if err != nil {
		log.Printf("[AUTH_OAUTH_CALLBACK] ERROR: Failed to generate JWT: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}
	log.Printf("[AUTH_OAUTH_CALLBACK_TIMING] jwt_generate=%s", time.Since(stepStart))
	stepStart = time.Now() // Reset timer for next step

	// Set token in cookie with anti-cache headers
	h.setAuthCookie(c, jwtToken)
	log.Printf("[AUTH_OAUTH_CALLBACK_TIMING] set_cookie=%s", time.Since(stepStart))
	stepStart = time.Now()

	redirectURL := os.Getenv("FRONTEND_URL")
	if redirectURL == "" {
		redirectURL = os.Getenv("AUTH_SUCCESS_REDIRECT_URL")
	}
	if redirectURL == "" {
		redirectURL = "http://localhost:3000" // Fallback default
	}
	
	log.Printf("[AUTH_OAUTH_CALLBACK] ✅ SUCCESS! Redirecting to %s", redirectURL)
	totalDuration := time.Since(overallStart)
	log.Printf("[AUTH_OAUTH_CALLBACK_TIMING] redirect_prep=%s", time.Since(stepStart))
	log.Printf("[AUTH_OAUTH_CALLBACK_TIMING] TOTAL_duration=%s", totalDuration)
	
	// Fast 302 redirect - browser follows immediately
	return c.Redirect(redirectURL, fiber.StatusFound)
}

// GetDevToken generates a JWT for a fake user for development/testing.
// This endpoint should ONLY be available in a development environment.
// @Summary Get Development Token
// @Description Generates a JWT for a test user (e.g., user_id '1'). Only for development.
// @Tags Auth
// @Produce json
// @Param user_id query string false "User ID to generate token for" default(1)
// @Success 200 {object} object{access_token=string, user_id=string, name=string, email=string}
// @Failure 403 {object} response.Response
// @Router /auth/dev/get-token [get]
func (h *AuthHandler) GetDevToken(c *fiber.Ctx) error {
	// CRITICAL: Only allow this in development environments.
	if os.Getenv("APP_ENV") != "development" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "This endpoint is for development use only.",
		})
	}

	userID := c.Query("user_id", "1") // Default to user_id "1"
	fakeUser := &models.User{
		ID:      userID, // <-- Perbaikan: UserID -> ID
		Email:   fmt.Sprintf("testuser-%s@example.com", userID),
		Name:    fmt.Sprintf("Test User %s", userID),
		Picture: "https://example.com/avatar.png", // <-- Perbaikan: AvatarURL -> Picture
	}

	token, err := h.authService.GenerateJWT(fakeUser)
	if err != nil {
		return response.InternalServerError(c, "Failed to generate dev token", err)
	}

	// For easy testing, return the token in the body.
	return c.JSON(fiber.Map{
		"access_token": token,
		"user_id":      fakeUser.ID, // <-- Perbaikan: fakeUser.UserID -> fakeUser.ID
		"name":         fakeUser.Name,
		"email":        fakeUser.Email,
	})
}

// Logout clears the auth cookie.
// @Summary Logout
// @Description Clears the auth cookie and ends the session
// @Tags Auth
// @Success 200 {object} map[string]string
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	h.clearAuthCookie(c)
	return c.JSON(fiber.Map{"status": "ok"})
}

// Tambahkan Method Baru ini untuk cek session
// GetMe validates the session cookie and returns the current user
// @Summary Get Current User
// @Description Returns the currently logged in user based on the auth cookie
// @Tags Auth
// @Success 200 {object} models.User
// @Router /auth/me [get]
func (h *AuthHandler) GetMe(c *fiber.Ctx) error {
    // User ID harusnya sudah di-set oleh AuthMiddleware di c.Locals
    userID, ok := c.Locals("user_id").(string)
    if !ok || userID == "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }

    user, err := h.authService.GetUserByID(c.Context(), userID)
    if err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
    }

    return c.JSON(user)
}
