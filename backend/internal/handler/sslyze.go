package handler

import (
	"context"
	"time"

	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type SslyzeHandler struct {
	service *service.SslyzeService
}

func NewSslyzeHandler(s *service.SslyzeService) *SslyzeHandler {
	return &SslyzeHandler{service: s}
}

// StartScan initiates an SSLyze scan
// @Summary Start SSLyze Scan
// @Description Run SSL/TLS configuration analysis
// @Tags SSLyze
// @Accept json
// @Produce json
// @Param target body object{target=string} true "Target Host:Port"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /sslyze/scan [post]
func (h *SslyzeHandler) StartScan(c *fiber.Ctx) error {
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
		return response.InternalServerError(c, "SSLyze scan failed", err)
	}

	return response.Success(c, "Scan completed", result)
}
