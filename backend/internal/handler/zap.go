package handler

import (
	"context"
	"net/url"
	"strings"
	"time"

	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type ZapHandler struct {
	service *service.ZapService
}

func NewZapHandler(s *service.ZapService) *ZapHandler {
	return &ZapHandler{service: s}
}

// StartScan initiates a full ZAP scan
// @Summary Start ZAP Scan
// @Description Run ZAP Spider and Active Scan
// @Tags ZAP
// @Accept json
// @Produce json
// @Param target body object{target=string} true "Target URL"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /zap/scan [post]
func (h *ZapHandler) StartScan(c *fiber.Ctx) error {
	var req struct {
		Target string `json:"target"`
	}

	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request payload", err)
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		return response.BadRequest(c, "Target is required", nil)
	}
	if !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
		target = "https://" + target
	}
	if _, err := url.ParseRequestURI(target); err != nil {
		return response.BadRequest(c, "Invalid request URL", err)
	}

	ctx, cancel := context.WithTimeout(c.Context(), 300*time.Second)
	defer cancel()

	result, err := h.service.ExecuteFullScan(ctx, target)
	if err != nil {
		return response.InternalServerError(c, "ZAP scan failed", err)
	}

	return response.Success(c, "ZAP scan completed", result)
}
