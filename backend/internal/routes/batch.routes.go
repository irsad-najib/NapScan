package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)	

func BatchRoutes(router fiber.Router, h *handler.BatchHandler) {
	// Changed to POST as it creates a resource
	router.Post("/batch/create", h.CreateBatch)
	router.Get("/batch/list", h.GetUserBatches)
	router.Get("/batch/:batch_id", h.GetBatchDetail)
}