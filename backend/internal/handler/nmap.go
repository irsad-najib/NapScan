package handler

import (
	"context"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type NmapHandler struct {
	service      *service.NmapService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewNmapHandler(s *service.NmapService, scanRepo repository.ScanResultRepository, batchService *service.BatchService) *NmapHandler {
	return &NmapHandler{service: s, scanRepo: scanRepo, batchService: batchService}
}

// StartFullScan initiates a full Nmap scan (TCP + UDP)
// @Summary Start Nmap Full Scan
// @Description Run parallel TCP and UDP Nmap scans on a target
// @Tags Nmap
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param target body object{target=string,batch_id=string} true "Target IP or Hostname"
// @Success 200 {object} service.CombinedScanResponse
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /nmap/scan [post]
func (h *NmapHandler) StartFullScan(c *fiber.Ctx) error {
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		return err // The error from ValidateBatchOwnership is already a fiber.Error
	}

	if req.Target == "" {
		return response.BadRequest(c, "Target is required", nil)
	}

	result, err := h.service.RunParallelScan(req.Target)
	if err != nil {
		return response.InternalServerError(c, "Scan failed", err)
	}

	result.BatchID = req.BatchID

	if h.scanRepo != nil {
		dbCtx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
		defer cancel()
		_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "nmap",
			Target:    req.Target,
			Result:    result,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
	}

	return c.Status(fiber.StatusOK).JSON(result)
}
