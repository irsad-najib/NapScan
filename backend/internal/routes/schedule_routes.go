package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func ScheduleRoutes(router fiber.Router, h *handler.SchedulerHandler) {
	group := router.Group("/schedule")

	group.Post("/", h.Create)
	group.Get("/", h.List)
	group.Delete("/:id", h.Delete)
	group.Post("/:id/pause", h.Pause)
	group.Post("/:id/resume", h.Resume)
}
