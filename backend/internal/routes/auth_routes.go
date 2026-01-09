package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func AuthRoutes(router fiber.Router, h *handler.AuthHandler) {
	g := router.Group("/auth")
	
	// Client-Side Flow (POST ID Token)
	g.Post("/google", h.GoogleLogin)
	
	// Server-Side Flow (GET Redirect & Callback)
	g.Get("/google/login", h.GoogleLoginRedirect)
	g.Get("/google/callback", h.GoogleCallback)
}
