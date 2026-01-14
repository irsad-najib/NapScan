package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func MobSFRoutes(router fiber.Router, h *handler.MobSFHandler) {
	mobsf := router.Group("/mobsf")
	mobsf.Post("/upload", h.UploadMobSFFile)
	mobsf.Post("/scan", h.StartMobSFScan)
}
