package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// CORSMiddleware enforces a CORS policy using Fiber
func CORSMiddleware() fiber.Handler {
	return cors.New(cors.Config{
		// Untuk development, kita izinkan semua origin.
		// PERINGATAN: Jangan gunakan "*" di produksi.
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: false, // Meskipun dengan AllowOrigins: "*", ini tetap praktik yang baik
	})
}
