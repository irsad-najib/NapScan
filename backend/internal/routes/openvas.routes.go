package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func OpenVASRoutes(router fiber.Router, h *handler.OpenVASHandler, scanHandler *handler.ScanHandler) {
	group := router.Group("/openvas")
	group.Get("/version", h.GetVersion)
	group.Post("/scan", h.StartScan)
	group.Get("/task/:taskId/status", h.GetTaskStatus)
	group.Get("/report/:reportId", h.GetScanReport)

	// Scan Control (Unified)
	group.Post("/scan/:task_id/stop", scanHandler.StopScan)
	group.Post("/scan/:task_id/resume", scanHandler.ResumeScan)
	group.Get("/scan/:task_id/status", scanHandler.GetStatus)
}
