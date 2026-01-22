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
	"github.com/google/uuid"
)

type NmapHandler struct {
	service      *service.NmapService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
	scanManager  *service.ScanManager
}

func NewNmapHandler(s *service.NmapService, scanRepo repository.ScanResultRepository, batchService *service.BatchService, scanManager *service.ScanManager) *NmapHandler {
	return &NmapHandler{
		service:      s,
		scanRepo:     scanRepo,
		batchService: batchService,
		scanManager:  scanManager,
	}
}

// StartFullScan initiates a full Nmap scan (TCP + UDP) - LEGACY SYNC VERSION
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
		return err
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

// StartScanAsync initiates an async Nmap scan (NEW)
// @Summary Start Nmap Scan (Async)
// @Description Start a Nmap scan asynchronously. Returns task_id immediately.
// @Tags Nmap
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param request body object{target=string,batch_id=string,scan_type=string} true "Scan Request"
// @Success 200 {object} models.ScanTaskResponse
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /nmap/scan/async [post]
func (h *NmapHandler) StartScanAsync(c *fiber.Ctx) error {
	log.Printf("[NMAP_ASYNC] Received async scan request")

	var req struct {
		Target   string `json:"target"`
		BatchID  string `json:"batch_id"`
		ScanType string `json:"scan_type"` // "single" or "parallel"
	}

	if err := c.BodyParser(&req); err != nil {
		log.Printf("[NMAP_ASYNC] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		return response.BadRequest(c, "batch_id is required", nil)
	}

	if req.Target == "" {
		return response.BadRequest(c, "target is required", nil)
	}

	if req.ScanType == "" {
		req.ScanType = "single" // default
	}

	// Validate batch ownership
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[NMAP_ASYNC] Batch ownership validation failed: %v", err)
		return err
	}

	// Get user ID from context (safe type assertion)
	userID := "unknown"
	if uid, ok := c.Locals("userID").(string); ok && uid != "" {
		userID = uid
	}

	// Create task
	taskID := uuid.New().String()
	ctx, cancel := context.WithCancel(context.Background())

	task := &models.ScanTask{
		BatchID:   req.BatchID,
		TaskID:    taskID,
		UserID:    userID,
		Target:    req.Target,
		Status:    models.StatusPending,
		Progress:  0,
		Error:     nil,
		Result:    []map[string]interface{}{},
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Cancel:    cancel,
	}

	// Register task with manager
	h.scanManager.Register(task)

	// Start scan in background
	go func() {
		var err error
		if req.ScanType == "parallel" {
			err = service.RunNmapParallelAsync(ctx, taskID, h.scanManager)
		} else {
			err = service.RunNmapAsync(ctx, taskID, h.scanManager)
		}

		if err != nil {
			log.Printf("[NMAP_ASYNC] Scan goroutine error: %v", err)
		}

		// Save to database if completed successfully
		if task, _ := h.scanManager.Get(taskID); task != nil && task.Status == models.StatusCompleted {
			if h.scanRepo != nil {
				dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer dbCancel()
				_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
					BatchID:   task.BatchID,
					Tool:      "nmap",
					Target:    task.Target,
					Result:    task.Result,
					CreatedAt: time.Now().UTC(),
				})
				if dbErr != nil {
					log.Printf("[NMAP_ASYNC] Failed to save to database: %v", dbErr)
				} else {
					log.Printf("[NMAP_ASYNC] Database insert success for task=%s", taskID)
				}
			}
		}
	}()

	log.Printf("[NMAP_ASYNC] Task created: task_id=%s, target=%s", taskID, req.Target)

	return response.Success(c, "scan started", fiber.Map{
		"task_id":  taskID,
		"status":   models.StatusRunning,
		"progress": 0,
	})
}
