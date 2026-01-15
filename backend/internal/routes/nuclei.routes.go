package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func NucleiRoutes(router fiber.Router, h *handler.NucleiHandler) {
	group := router.Group("/nuclei")
	
	// Sync endpoint (original - with timeout issues)
	group.Post("/scan", h.StartScan)
	
	// Async endpoints (recommended for long-running scans)
	group.Post("/scan/async", h.StartScanAsync)
	group.Get("/scan/async/:taskId", h.GetTaskStatus)
	group.Get("/scan/async/:taskId/result", h.GetTaskResult)
}
