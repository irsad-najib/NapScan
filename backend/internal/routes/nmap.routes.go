package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func NmapRoutes(router fiber.Router, h *handler.NmapHandler) {
	router.Post("/nmap/scan", h.StartFullScan)
}
