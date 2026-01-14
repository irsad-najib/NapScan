package middleware

import (
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// CORSMiddleware enforces a CORS policy using Fiber
func CORSMiddleware() fiber.Handler {
	allowOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOW_ORIGINS"))
	if allowOrigins == "" {
		allowOrigins = "http://localhost:3000"
	}

	return cors.New(cors.Config{
		// Untuk development, kita izinkan semua origin.
		// PERINGATAN: Jangan gunakan "*" di produksi.
		AllowOrigins: allowOrigins,
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	})
}
