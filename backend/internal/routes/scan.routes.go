package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

// ScanControlRoutes registers global scan control endpoints
// These work for all scanners (Nmap, FFUF, Nuclei, etc)
func ScanControlRoutes(router fiber.Router, scanHandler *handler.ScanHandler) {
	group := router.Group("/scan")
	
	// Global scan control endpoints
	group.Post("/:task_id/stop", scanHandler.StopScan)
	group.Get("/:task_id/status", scanHandler.GetStatus)
	group.Get("/:task_id/report", scanHandler.GetReport)
}
