package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func FfufRoutes(router fiber.Router, ffufHandler *handler.FfufHandler, scanHandler *handler.ScanHandler) {
	group := router.Group("/ffuf")
	
	// Legacy sync endpoint
	group.Post("/scan", ffufHandler.StartScan)
	
	// NEW async endpoint
	group.Post("/scan/async", ffufHandler.StartScanAsync)
	
	// Common scan control endpoints
	group.Post("/scan/:task_id/stop", scanHandler.StopScan)
	group.Get("/scan/:task_id/status", scanHandler.GetStatus)
	group.Get("/scan/:task_id/report", scanHandler.GetReport)
}
