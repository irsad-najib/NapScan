package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func NucleiRoutes(router fiber.Router, h *handler.NucleiHandler) {
	group := router.Group("/nuclei")
	group.Post("/scan", h.StartScan)
}
