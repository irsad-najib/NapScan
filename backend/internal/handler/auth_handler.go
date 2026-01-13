package handler

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/service"
	"os"
	"strings"
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
	c.Cookie(cookie)
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

	return c.JSON(models.AuthResponse{
		AccessToken: "",
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

	// Optional: redirect to frontend after setting cookie (no token in URL).
	if redirect := strings.TrimSpace(os.Getenv("AUTH_SUCCESS_REDIRECT_URL")); redirect != "" {
		return c.Redirect(redirect)
	}

	// Option 1: Redirect to frontend with token
	// return c.Redirect("http://localhost:3000/auth/success?token=" + token)
	
	// Option 2: Return JSON (for API testing)
	return c.JSON(models.AuthResponse{
		AccessToken: "",
		User:        *user,
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
