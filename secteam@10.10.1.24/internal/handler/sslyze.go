package handler

import (
	"context"
	"log"
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
	log.Printf("[SSLYZE] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		log.Printf("[SSLYZE] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		log.Printf("[SSLYZE] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	log.Printf("[SSLYZE] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[SSLYZE] Batch ownership validation failed: %v", err)
		return err
	}

	if req.Target == "" {
		log.Printf("[SSLYZE] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	log.Printf("[SSLYZE] Starting scan on target=%s", req.Target)
	ctx, cancel := context.WithTimeout(c.Context(), 120*time.Second)
	defer cancel()

	result, err := h.service.ExecuteScan(ctx, req.Target)
	if err != nil {
		log.Printf("[SSLYZE] Scan execution failed: %v", err)
		return response.InternalServerError(c, "SSLyze scan failed", err)
	}
	log.Printf("[SSLYZE] Scan completed successfully")

	if h.scanRepo != nil {
		_, dbErr := h.scanRepo.Insert(ctx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "sslyze",
			Target:    req.Target,
			Result:    result,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			log.Printf("[SSLYZE] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		log.Printf("[SSLYZE] Database insert success")
	}

	if resMap, ok := result.(map[string]interface{}); ok {
		resMap["batch_id"] = req.BatchID
	}

	log.Printf("[SSLYZE] Request completed successfully")
	return response.Success(c, "Scan completed", result)
}
