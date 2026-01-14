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

type FfufHandler struct {
	service      *service.FfufService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewFfufHandler(s *service.FfufService, scanRepo repository.ScanResultRepository, batchService *service.BatchService) *FfufHandler {
	return &FfufHandler{service: s, scanRepo: scanRepo, batchService: batchService}
}

// StartScan initiates a FFUF scan
// @Summary Start FFUF Scan
// @Description Run directory fuzzing using FFUF
// @Tags FFUF
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param target body object{target=string,batch_id=string} true "Target URL"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /ffuf/scan [post]
func (h *FfufHandler) StartScan(c *fiber.Ctx) error {
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

	if req.Target == "" {
		return response.BadRequest(c, "Target is required", nil)
	}

	ctx, cancel := context.WithTimeout(c.Context(), 120*time.Second)
	defer cancel()

	result, err := h.service.ExecuteScan(ctx, req.Target)
	if err != nil {
		return response.InternalServerError(c, "FFUF scan failed", err)
	}

	if resMap, ok := result.(map[string]interface{}); ok {
		resMap["batch_id"] = req.BatchID
	}

	if h.scanRepo != nil {
		dbCtx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
		defer cancel()
		_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "ffuf",
			Target:    req.Target,
			Result:    result,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
	}

	return response.Success(c, "Scan completed", result)
}
