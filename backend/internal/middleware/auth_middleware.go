package middleware

import (
	"os"
	"strings"

	"napscan-be/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware validates the JWT token and injects user info into context
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Prefer HttpOnly cookie for browser clients.
		cookieName := strings.TrimSpace(os.Getenv("AUTH_COOKIE_NAME"))
		if cookieName == "" {
			cookieName = "napscan_access_token"
		}
		tokenString := strings.TrimSpace(c.Cookies(cookieName))
		if tokenString == "" {
			// Compatibility: accept a generic cookie name too.
			tokenString = strings.TrimSpace(c.Cookies("access_token"))
		}
		if tokenString == "" {
			// Fallback to Authorization: Bearer <token> for API clients.
			authHeader := c.Get("Authorization")
			if authHeader == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Missing authentication (cookie or Authorization header)",
				})
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Invalid authorization header format",
				})
			}
			tokenString = parts[1]
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

		return c.Next()
	}
}
