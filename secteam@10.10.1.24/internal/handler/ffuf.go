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
	log.Printf("[FFUF] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		log.Printf("[FFUF] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		log.Printf("[FFUF] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	log.Printf("[FFUF] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[FFUF] Batch ownership validation failed: %v", err)
		return err
	}

	if req.Target == "" {
		log.Printf("[FFUF] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	log.Printf("[FFUF] Starting scan on target=%s", req.Target)
	ctx, cancel := context.WithTimeout(c.Context(), 120*time.Second)
	defer cancel()

	result, err := h.service.ExecuteScan(ctx, req.Target)
	if err != nil {
		log.Printf("[FFUF] Scan execution failed: %v", err)
		return response.InternalServerError(c, "FFUF scan failed", err)
	}
	log.Printf("[FFUF] Scan completed successfully")

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
			log.Printf("[FFUF] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		log.Printf("[FFUF] Database insert success")
	}

	log.Printf("[FFUF] Request completed successfully")
	return response.Success(c, "Scan completed", result)
}
