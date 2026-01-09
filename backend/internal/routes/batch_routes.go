package routes

import (
	"napscan-be/internal/handler"
	"napscan-be/internal/middleware"

	"github.com/gofiber/fiber/v2"
)

func BatchRoutes(router fiber.Router, h *handler.BatchHandler) {
	// Group is typically /api passed in
	// We want /api/a, /api/b etc. but protected
	
	protected := router.Group("/", middleware.AuthMiddleware()) 

	// Fan-in endpoints
	protected.Post("/a", h.HandleScanPartA)
	protected.Post("/b", h.HandleScanPartB)
	protected.Post("/c", h.HandleScanPartC)
	protected.Post("/d", h.HandleScanPartD)
	protected.Post("/e", h.HandleScanPartE)

	// Result Retrieval
	protected.Get("/analysis/:batch_id", h.GetBatchResult)
}
