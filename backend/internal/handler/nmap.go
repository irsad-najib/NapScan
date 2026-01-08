package handler

import (
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type NmapHandler struct {
	service *service.NmapService
}

func NewNmapHandler(s *service.NmapService) *NmapHandler {
	return &NmapHandler{service: s}
}

// StartFullScan initiates a full Nmap scan (TCP + UDP)
// @Summary Start Nmap Full Scan
// @Description Run parallel TCP and UDP Nmap scans on a target
// @Tags Nmap
// @Accept json
// @Produce json
// @Param target body object{target=string} true "Target IP or Hostname"
// @Success 200 {object} service.CombinedScanResponse
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /nmap/scan [post]
func (h *NmapHandler) StartFullScan(c *fiber.Ctx) error {
	var req struct {
		Target string `json:"target"`
	}

	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.Target == "" {
		return response.BadRequest(c, "Target is required", nil)
	}

	result, err := h.service.RunParallelScan(req.Target)
	if err != nil {
		return response.InternalServerError(c, "Scan failed", err)
	}

	return c.Status(fiber.StatusOK).JSON(result)
}
