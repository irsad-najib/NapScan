package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func LifecycleRoutes(router fiber.Router, h *handler.LifecycleHandler) {
	group := router.Group("/files")
	group.Get("/:id/status", h.GetFileStatus)
	group.Post("/:id/decision", h.SubmitUserDecision)
}
