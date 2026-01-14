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

type SslyzeHandler struct {
	service      *service.SslyzeService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewSslyzeHandler(s *service.SslyzeService, scanRepo repository.ScanResultRepository, batchService *service.BatchService) *SslyzeHandler {
	return &SslyzeHandler{service: s, scanRepo: scanRepo, batchService: batchService}
}

// StartScan initiates an SSLyze scan
// @Summary Start SSLyze Scan
// @Description Run SSL/TLS configuration analysis
// @Tags SSLyze
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param target body object{target=string,batch_id=string} true "Target Host:Port"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /sslyze/scan [post]
func (h *SslyzeHandler) StartScan(c *fiber.Ctx) error {
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
		return response.InternalServerError(c, "SSLyze scan failed", err)
	}

	if h.scanRepo != nil {
		_, dbErr := h.scanRepo.Insert(ctx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "sslyze",
			Target:    req.Target,
			Result:    result,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
	}

	if resMap, ok := result.(map[string]interface{}); ok {
		resMap["batch_id"] = req.BatchID
	}

	return response.Success(c, "Scan completed", result)
}
