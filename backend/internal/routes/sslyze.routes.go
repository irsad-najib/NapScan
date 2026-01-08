package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func SslyzeRoutes(router fiber.Router, h *handler.SslyzeHandler) {
	group := router.Group("/sslyze")
	group.Post("/scan", h.StartScan)
}
