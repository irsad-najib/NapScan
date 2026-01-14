package middleware

import (
	"fmt"
	"log"
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
				log.Printf("!!! DEBUG: Overriding auth. Using User ID: %s !!!", debugUserID)
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
		tokenString := strings.TrimSpace(c.Cookies(cookieName))

		// Fallback to Authorization header for API clients (like Swagger)
		if tokenString == "" {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if tokenString == "" {
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
