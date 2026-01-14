package handler

import (
	"context"
	"net/url"
	"strings"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type ZapHandler struct {
	service      *service.ZapService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewZapHandler(s *service.ZapService, scanRepo repository.ScanResultRepository, batchService *service.BatchService) *ZapHandler {
	return &ZapHandler{service: s, scanRepo: scanRepo, batchService: batchService}
}

// StartScan initiates a full ZAP scan
// @Summary Start ZAP Scan
// @Description Run ZAP Spider and Active Scan
// @Tags ZAP
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param target body object{target=string,batch_id=string} true "Target URL"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /zap/scan [post]
func (h *ZapHandler) StartScan(c *fiber.Ctx) error {
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

	result["batch_id"] = req.BatchID

	if h.scanRepo != nil {
		dbCtx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
		defer cancel()
		_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "zap",
			Target:    target,
			Result:    result,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
	}

	return response.Success(c, "ZAP scan completed", result)
}
