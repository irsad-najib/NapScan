package handler

import (
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/service"

	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		authService: service.NewAuthService(),
	}
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

	return c.JSON(models.AuthResponse{
		AccessToken: token,
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
	url := h.authService.GetGoogleLoginURL()
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

	// Option 1: Redirect to frontend with token
	// return c.Redirect("http://localhost:3000/auth/success?token=" + token)
	
	// Option 2: Return JSON (for API testing)
	return c.JSON(models.AuthResponse{
		AccessToken: token,
		User:        *user,
	})
}
