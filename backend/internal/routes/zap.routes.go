package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func ZapRoutes(router fiber.Router, h *handler.ZapHandler) {
	group := router.Group("/zap")
	group.Post("/scan", h.StartScan)
}
