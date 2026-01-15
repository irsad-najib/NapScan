package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func FfufRoutes(router fiber.Router, h *handler.FfufHandler) {
	group := router.Group("/ffuf")
	group.Post("/scan", h.StartScan)
}
