package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func OpenVASRoutes(router fiber.Router, h *handler.OpenVASHandler) {
	group := router.Group("/openvas")
	group.Get("/version", h.GetVersion)
	group.Post("/scan", h.StartScan)
	group.Get("/task/:taskId/status", h.GetTaskStatus)
	group.Get("/report/:reportId", h.GetScanReport)
}
