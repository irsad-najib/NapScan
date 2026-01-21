package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func ZapRoutes(router fiber.Router, zapHandler *handler.ZapHandler, scanHandler *handler.ScanHandler) {
	group := router.Group("/zap")
	
	// Legacy sync endpoint
	group.Post("/scan", zapHandler.StartScan)
	
	// NEW async endpoint
	group.Post("/scan/async", zapHandler.StartScanAsync)
	
	// Common scan control endpoints
	group.Post("/scan/:task_id/stop", scanHandler.StopScan)
	group.Get("/scan/:task_id/status", scanHandler.GetStatus)
	group.Get("/scan/:task_id/report", scanHandler.GetReport)
}
