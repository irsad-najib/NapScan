package handler

import (
	"github.com/gofiber/fiber/v2"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// Check returns server health status
// @Summary Health Check
// @Description Checks if the server is running
// @Tags Health
// @Accept json
// @Produce json
// @Success 200 {object}  map[string]interface{}
// @Router /health [get]
func (h *HealthHandler) Check(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Server is healthy",
		"timestamp":  c.Context().Time(),
	})
}
