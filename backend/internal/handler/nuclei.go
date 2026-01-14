package handler

import (
	"context"
	"strings"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type NucleiHandler struct {
	service      *service.NucleiService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewNucleiHandler(s *service.NucleiService, scanRepo repository.ScanResultRepository, batchService *service.BatchService) *NucleiHandler {
	return &NucleiHandler{service: s, scanRepo: scanRepo, batchService: batchService}
}

// StartScan initiates a Nuclei scan
// @Summary Start Nuclei Scan
// @Description Run Nuclei scan on a target
// @Tags Nuclei
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param target body object{target=string,batch_id=string} true "Target URL or Hostname"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /nuclei/scan [post]
func (h *NucleiHandler) StartScan(c *fiber.Ctx) error {
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
		return err
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

	payload := fiber.Map{
		"target":   req.Target,
		"results":  results,
		"batch_id": req.BatchID,
	}

	if h.scanRepo != nil {
		dbCtx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
		defer cancel()
		_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "nuclei",
			Target:    req.Target,
			Result:    payload,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
	}

	return response.Success(c, "Scan completed", payload)
}
