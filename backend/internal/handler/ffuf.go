package handler

import (
	"context"
	"time"

	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type FfufHandler struct {
service *service.FfufService
}

func NewFfufHandler(s *service.FfufService) *FfufHandler {
return &FfufHandler{service: s}
}

// StartScan initiates a FFUF scan
// @Summary Start FFUF Scan
// @Description Run directory fuzzing using FFUF
// @Tags FFUF
// @Accept json
// @Produce json
// @Param target body object{target=string} true "Target URL"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /ffuf/scan [post]
func (h *FfufHandler) StartScan(c *fiber.Ctx) error {
var req struct {
Target string `json:"target"`
}

if err := c.BodyParser(&req); err != nil {
return response.BadRequest(c, "Invalid request payload", err)
}

if req.Target == "" {
return response.BadRequest(c, "Target is required", nil)
}

ctx, cancel := context.WithTimeout(c.Context(), 120*time.Second)
defer cancel()

result, err := h.service.ExecuteScan(ctx, req.Target)
if err != nil {
return response.InternalServerError(c, "FFUF scan failed", err)
}

return response.Success(c, "Scan completed", result)
}
