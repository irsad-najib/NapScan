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
	log.Printf("[NMAP] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		log.Printf("[NMAP] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		log.Printf("[NMAP] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	log.Printf("[NMAP] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[NMAP] Batch ownership validation failed: %v", err)
		return err // The error from ValidateBatchOwnership is already a fiber.Error
	}

	if req.Target == "" {
		log.Printf("[NMAP] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	log.Printf("[NMAP] Starting parallel scan on target=%s", req.Target)
	result, err := h.service.RunParallelScan(req.Target)
	if err != nil {
		log.Printf("[NMAP] Scan execution failed: %v", err)
		return response.InternalServerError(c, "Scan failed", err)
	}
	log.Printf("[NMAP] Scan completed successfully")

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
			log.Printf("[NMAP] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		log.Printf("[NMAP] Database insert success")
	}

	log.Printf("[NMAP] Request completed successfully")
	return c.Status(fiber.StatusOK).JSON(result)
}
