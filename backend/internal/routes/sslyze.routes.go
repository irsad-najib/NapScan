package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func SslyzeRoutes(router fiber.Router, sslyzeHandler *handler.SslyzeHandler, scanHandler *handler.ScanHandler) {
	group := router.Group("/sslyze")
	
	// Legacy sync endpoint
	group.Post("/scan", sslyzeHandler.StartScan)
	
	// NEW async endpoint
	group.Post("/scan/async", sslyzeHandler.StartScanAsync)
	
	// Common scan control endpoints
	group.Post("/scan/:task_id/stop", scanHandler.StopScan)
	group.Get("/scan/:task_id/status", scanHandler.GetStatus)
	group.Get("/scan/:task_id/report", scanHandler.GetReport)
}
