package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func NmapRoutes(router fiber.Router, nmapHandler *handler.NmapHandler, scanHandler *handler.ScanHandler) {
	group := router.Group("/nmap")
	
	// Legacy sync endpoint (existing)
	group.Post("/scan", nmapHandler.StartFullScan)
	
	// NEW async endpoint
	group.Post("/scan/async", nmapHandler.StartScanAsync)
	
	// Common scan control endpoints (managed by ScanHandler)
	group.Post("/scan/:task_id/stop", scanHandler.StopScan)
	group.Get("/scan/:task_id/status", scanHandler.GetStatus)
	group.Get("/scan/:task_id/report", scanHandler.GetReport)
}
