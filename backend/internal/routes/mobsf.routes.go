package routes

import (
	"napscan-be/internal/handler"

	"github.com/gofiber/fiber/v2"
)

func MobSFRoutes(router fiber.Router) {
	mobsf := router.Group("/mobsf")
	mobsf.Post("/upload", handler.UploadMobSFFile)
}
