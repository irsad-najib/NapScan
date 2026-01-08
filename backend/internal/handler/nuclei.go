package handler

import (
	"context"
	"strings"
	"time"

	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type NucleiHandler struct {
	service *service.NucleiService
}

func NewNucleiHandler(s *service.NucleiService) *NucleiHandler {
	return &NucleiHandler{service: s}
}

// StartScan initiates a Nuclei scan
// @Summary Start Nuclei Scan
// @Description Run Nuclei scan on a target
// @Tags Nuclei
// @Accept json
// @Produce json
// @Param target body object{target=string} true "Target URL or Hostname"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /nuclei/scan [post]
func (h *NucleiHandler) StartScan(c *fiber.Ctx) error {
	var req struct {
		Target string `json:"target"`
	}

	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request payload", err)
	}

	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		return response.BadRequest(c, "Target is required", nil)
	}

	ctx, cancel := context.WithTimeout(c.Context(), 300*time.Second)
	defer cancel()

	results, err := h.service.ExecuteScan(ctx, req.Target)
	if err != nil {
		return response.InternalServerError(c, "Nuclei scan failed", err)
	}

	return response.Success(c, "Scan completed", fiber.Map{
		"target":  req.Target,
		"results": results,
	})
}
