package middleware

import (
	"fmt"
	"napscan-be/pkg/logger"
	"os"
	"strings"

	"napscan-be/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware validates the JWT token and injects user info into context
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// --- DEVELOPMENT-ONLY DEBUGGING OVERRIDE ---
		if os.Getenv("APP_ENV") == "development" {
			debugUserID := c.Get("X-Debug-User-ID")
			if debugUserID != "" {
				logger.Warn("!!! DEBUG: Overriding auth. Using User ID: %s !!!", debugUserID)
				c.Locals("user_id", debugUserID)
				c.Locals("email", fmt.Sprintf("debug-%s@example.com", debugUserID))
				c.Locals("name", fmt.Sprintf("Debug User %s", debugUserID))
				return c.Next()
			}
		}
		// --- END DEBUGGING OVERRIDE ---

		cookieName := strings.TrimSpace(os.Getenv("AUTH_COOKIE_NAME"))
		if cookieName == "" {
			cookieName = "napscan_access_token"
		}

		cookieDebug := false
		if os.Getenv("APP_ENV") == "development" {
			v := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_COOKIE_DEBUG")))
			cookieDebug = v == "1" || v == "true" || v == "yes"
		}
		if cookieDebug {
			origin := strings.TrimSpace(c.Get("Origin"))
			referer := strings.TrimSpace(c.Get("Referer"))
			logger.Debug("[AUTH_COOKIE_DEBUG] incoming %s %s origin=%q referer=%q cookie_name=%q cookie_present=%v",
				c.Method(),
				c.OriginalURL(),
				origin,
				referer,
				cookieName,
				strings.TrimSpace(c.Cookies(cookieName)) != "",
			)
		}

		// Extra, targeted debug for /api/auth/me: show whether auth inputs exist.
		// We NEVER log the raw token; only presence/length.
		if cookieDebug && c.Method() == fiber.MethodGet && strings.HasPrefix(c.Path(), "/api/auth/me") {
			cookieVal := strings.TrimSpace(c.Cookies(cookieName))
			authHeader := strings.TrimSpace(c.Get("Authorization"))
			hasBearer := strings.HasPrefix(authHeader, "Bearer ") && len(strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))) > 0
			bearerLen := 0
			if hasBearer {
				bearerLen = len(strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")))
			}
			logger.Debug("[AUTH_ME_DEBUG] cookie_present=%v cookie_len=%d bearer_present=%v bearer_len=%d",
				cookieVal != "",
				len(cookieVal),
				hasBearer,
				bearerLen,
			)
		}

		tokenString := strings.TrimSpace(c.Cookies(cookieName))

		// Fallback to Authorization header for API clients (like Swagger)
		if tokenString == "" {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
				if cookieDebug {
					logger.Debug("[AUTH_COOKIE_DEBUG] using Authorization header fallback (bearer_present=%v)", tokenString != "")
				}
			}
		}

		if tokenString == "" {
			if cookieDebug && c.Method() == fiber.MethodGet && strings.HasPrefix(c.Path(), "/api/auth/me") {
				logger.Debug("[AUTH_ME_DEBUG] unauthorized: no cookie and no bearer")
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing authentication token",
			})
		}

		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			secret = "dev-secret-key-change-in-prod"
		}

		// Parse and validate
		token, err := jwt.ParseWithClaims(tokenString, &models.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Validate signing algorithm
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.ErrUnauthorized
			}
			return []byte(secret), nil
		})

		if err != nil || !token.Valid {
			if cookieDebug && c.Method() == fiber.MethodGet && strings.HasPrefix(c.Path(), "/api/auth/me") {
				logger.Debug("[AUTH_ME_DEBUG] jwt_invalid valid=%v err=%v", token != nil && token.Valid, err)
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		claims, ok := token.Claims.(*models.JWTCustomClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token claims",
			})
		}

		// Store in locals for handlers to use
		c.Locals("user_id", claims.UserID)
		c.Locals("email", claims.Email)
		c.Locals("name", claims.Name)
		if cookieDebug && c.Method() == fiber.MethodGet && strings.HasPrefix(c.Path(), "/api/auth/me") {
			logger.Debug("[AUTH_ME_DEBUG] ok user_id=%q", claims.UserID)
		}

		return c.Next()
	}
}
