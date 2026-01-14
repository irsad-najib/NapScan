package routes

import (
	"napscan-be/internal/handler"
	"napscan-be/internal/middleware" // Tambahkan Import ini

	"github.com/gofiber/fiber/v2"
)

func AuthRoutes(router fiber.Router, h *handler.AuthHandler) {
	auth := router.Group("/auth")

	// OAuth Routes
	auth.Post("/google", h.GoogleLogin)
	auth.Get("/google/login", h.GoogleLoginRedirect)
	auth.Get("/google/callback", h.GoogleCallback)
	auth.Post("/logout", h.Logout)
	
	// Route Baru: Cek Session User
	// Menggunakan Middleware AuthMiddleware untuk validasi cookie
	auth.Get("/me", middleware.AuthMiddleware(), h.GetMe)

	// Development-only route to get a test token
	auth.Get("/dev/get-token", h.GetDevToken)
}
