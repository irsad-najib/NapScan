package handler

import (
	"context"
	"log"
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
	log.Printf("[NUCLEI] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		log.Printf("[NUCLEI] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		log.Printf("[NUCLEI] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	log.Printf("[NUCLEI] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[NUCLEI] Batch ownership validation failed: %v", err)
		return err
	}

	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		log.Printf("[NUCLEI] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	log.Printf("[NUCLEI] Starting scan on target=%s", req.Target)
	ctx, cancel := context.WithTimeout(c.Context(), 300*time.Second)
	defer cancel()

	results, err := h.service.ExecuteScan(ctx, req.Target)
	if err != nil {
		log.Printf("[NUCLEI] Scan execution failed: %v", err)
		return response.InternalServerError(c, "Nuclei scan failed", err)
	}
	log.Printf("[NUCLEI] Scan completed successfully")

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
			log.Printf("[NUCLEI] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		log.Printf("[NUCLEI] Database insert success")
	}

	log.Printf("[NUCLEI] Request completed successfully")
	return response.Success(c, "Scan completed", payload)
}
