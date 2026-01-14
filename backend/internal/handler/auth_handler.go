package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"
	"os"
	"strings" // Pastikan import ini ada
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

func isCookieDebugEnabled() bool {
	if strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))) != "development" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_COOKIE_DEBUG")))
	return v == "1" || v == "true" || v == "yes"
}

func (h *AuthHandler) setAuthCookie(c *fiber.Ctx, jwtToken string) {
	cookie := &fiber.Cookie{
		Name:     authCookieName(),
		Value:    jwtToken,
		HTTPOnly: true,
		Secure:   isSecureCookie(),
		SameSite: sameSiteMode(),
		Path:     "/",
		// Access token lifetime should match JWT exp; keep it aligned.
		Expires: time.Now().Add(24 * time.Hour),
	}
	// If SameSite=None is requested, Secure must be true for modern browsers.
	if strings.EqualFold(cookie.SameSite, "None") {
		cookie.Secure = true
	}
	if isCookieDebugEnabled() {
		prefix := jwtToken
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		log.Printf("[AUTH_COOKIE_DEBUG] set cookie name=%q secure=%v samesite=%q path=%q expires=%s token_prefix=%q token_len=%d",
			cookie.Name,
			cookie.Secure,
			cookie.SameSite,
			cookie.Path,
			cookie.Expires.Format(time.RFC3339),
			prefix,
			len(jwtToken),
		)
	}
	c.Cookie(cookie)
}

func (h *AuthHandler) clearAuthCookie(c *fiber.Ctx) {
	if isCookieDebugEnabled() {
		log.Printf("[AUTH_COOKIE_DEBUG] clear cookie name=%q", authCookieName())
	}
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

	// CSRF protection for OAuth redirect flow.
	c.Cookie(&fiber.Cookie{
		Name:     defaultOAuthStateCookie,
		Value:    state,
		HTTPOnly: true,
		Secure:   isSecureCookie(),
		SameSite: "Lax",
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
	})

	url := h.authService.GetGoogleLoginURL(state)
	log.Printf("Redirecting to Google OAuth: %s", url)
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
	code := c.Query("code")
	if code == "" {
		log.Printf("Google callback error: code not found")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Code not found"})
	}

	// Validate OAuth state to prevent CSRF.
	state := c.Query("state")
	expectedState := c.Cookies(defaultOAuthStateCookie)
	if expectedState == "" || state == "" || state != expectedState {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid oauth state"})
	}
	// One-time use
	c.Cookie(&fiber.Cookie{
		Name:     defaultOAuthStateCookie,
		Value:    "",
		HTTPOnly: true,
		Secure:   isSecureCookie(),
		SameSite: "Lax",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	log.Printf("Handling Google callback with code: %s...", code[:10])

	user, err := h.authService.HandleGoogleCallback(c.Context(), code)
	if err != nil {
		log.Printf("Failed to handle Google callback: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to handle callback: " + err.Error()})
	}

	log.Printf("User authenticated: %s (%s)", user.Name, user.Email)

	token, err := h.authService.GenerateJWT(user)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate session"})
	}

	h.setAuthCookie(c, token)

	// UBAH DISINI: Redirect bersih tanpa query params
	if redirect := strings.TrimSpace(os.Getenv("AUTH_SUCCESS_REDIRECT_URL")); redirect != "" {
		// Browser sudah punya Cookie, jadi langsung redirect aja
		return c.Redirect(redirect)
	}

	// Jika tidak ada redirect URL, return response biasa (opsional)
	return c.JSON(models.AuthResponse{
		AccessToken: "", // Kosongkan karena sudah ada di cookie
		User:        *user,
	})
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
