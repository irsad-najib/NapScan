package middleware

import (
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// CORSMiddleware enforces a CORS policy using Fiber
func CORSMiddleware() fiber.Handler {
	isDev := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))) == "development"
	
	allowOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOW_ORIGINS"))
	if allowOrigins == "" {
		allowOrigins = "http://localhost:3000"
	}

	config := cors.Config{
		AllowOrigins:     allowOrigins,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}

	// DEVELOPMENT MODE: Auto-accept localhost + ngrok + custom origins
	// Ini membuat development lebih mudah tanpa perlu update .env setiap kali ngrok restart
	if isDev {
		config.AllowOriginsFunc = func(origin string) bool {
			origin = strings.ToLower(strings.TrimSpace(origin))
			
			// Allow localhost pada port apapun
			if strings.HasPrefix(origin, "http://localhost:") || 
			   strings.HasPrefix(origin, "https://localhost:") ||
			   origin == "http://localhost" || 
			   origin == "https://localhost" {
				return true
			}
			
			// Allow semua ngrok URLs (ngrok-free.app, ngrok.io, dll)
			if strings.Contains(origin, ".ngrok-free.app") || 
			   strings.Contains(origin, ".ngrok.io") ||
			   strings.Contains(origin, ".ngrok.app") {
				return true
			}
			
			// Allow 127.0.0.1
			if strings.HasPrefix(origin, "http://127.0.0.1:") || 
			   strings.HasPrefix(origin, "https://127.0.0.1:") {
				return true
			}
			
			// Check manual CORS_ALLOW_ORIGINS list
			allowedList := strings.Split(allowOrigins, ",")
			for _, allowed := range allowedList {
				if strings.TrimSpace(strings.ToLower(allowed)) == origin {
					return true
				}
			}
			
			return false
		}
	}

	return cors.New(config)
}
