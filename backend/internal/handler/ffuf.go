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

type FfufHandler struct {
	service      *service.FfufService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
	scanManager  *service.ScanManager
}

func NewFfufHandler(s *service.FfufService, scanRepo repository.ScanResultRepository, batchService *service.BatchService, scanManager *service.ScanManager) *FfufHandler {
	return &FfufHandler{
		service:      s,
		scanRepo:     scanRepo,
		batchService: batchService,
		scanManager:  scanManager,
	}
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

// StartScanAsync initiates an async FFUF scan
// @Summary Start FFUF Scan (Async)
// @Description Start a FFUF scan asynchronously. Returns task_id immediately.
// @Tags FFUF
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param request body object{target=string,batch_id=string} true "Scan Request"
// @Success 200 {object} models.ScanTaskResponse
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /ffuf/scan/async [post]
func (h *FfufHandler) StartScanAsync(c *fiber.Ctx) error {
	log.Printf("[FFUF_ASYNC] Received async scan request")

	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		log.Printf("[FFUF_ASYNC] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		return response.BadRequest(c, "batch_id is required", nil)
	}

	if req.Target == "" {
		return response.BadRequest(c, "target is required", nil)
	}

	// Validate batch ownership
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[FFUF_ASYNC] Batch ownership validation failed: %v", err)
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
		Tool:      "ffuf",
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
		err := service.RunFfufAsync(ctx, taskID, h.scanManager)
		if err != nil {
			log.Printf("[FFUF_ASYNC] Scan goroutine error: %v", err)
		}

		// Save to database if completed successfully
		if task, _ := h.scanManager.Get(taskID); task != nil && task.Status == models.StatusCompleted {
			if h.scanRepo != nil {
				dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer dbCancel()
				_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
					BatchID:   task.BatchID,
					Tool:      "ffuf",
					Target:    task.Target,
					ResultRaw: task.ResultRaw,
					CreatedAt: time.Now().UTC(),
				})
				if dbErr != nil {
					log.Printf("[FFUF_ASYNC] Failed to save to database: %v", dbErr)
				} else {
					log.Printf("[FFUF_ASYNC] Database insert success for task=%s", taskID)
				}
			}
		}
	}()

	log.Printf("[FFUF_ASYNC] Task created: task_id=%s, target=%s", taskID, req.Target)

	return response.Success(c, "scan started", fiber.Map{
		"task_id":  taskID,
		"status":   models.StatusRunning,
		"progress": 0,
	})
}
