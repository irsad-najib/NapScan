package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// CORSMiddleware enforces a CORS policy using Fiber
func CORSMiddleware() fiber.Handler {
	config := cors.Config{
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}

	// User requested to allow "anyone" (all origins) for both dev and prod
	// while keeping AllowCredentials: true.
	config.AllowOriginsFunc = func(origin string) bool {
		return true // Allow all origins
	}

	return cors.New(config)
}
