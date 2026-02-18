package handler

import (
	"context"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/service"
	"napscan-be/pkg/logger"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type SslyzeHandler struct {
	service      *service.SslyzeService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
	scanManager  *service.ScanManager
}

func NewSslyzeHandler(s *service.SslyzeService, scanRepo repository.ScanResultRepository, batchService *service.BatchService, scanManager *service.ScanManager) *SslyzeHandler {
	return &SslyzeHandler{
		service:      s,
		scanRepo:     scanRepo,
		batchService: batchService,
		scanManager:  scanManager,
	}
}

// StartScan initiates an SSLyze scan (LEGACY SYNC)
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
	logger.Debug("[SSLYZE] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("[SSLYZE] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		logger.Warn("[SSLYZE] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	logger.Debug("[SSLYZE] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		logger.Warn("[SSLYZE] Batch ownership validation failed: %v", err)
		return err
	}

	if req.Target == "" {
		logger.Warn("[SSLYZE] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	logger.Info("[SSLYZE] Starting scan on target=%s", req.Target)
	ctx, cancel := context.WithTimeout(c.Context(), 120*time.Second)
	defer cancel()

	result, err := h.service.ExecuteScan(ctx, req.Target)
	if err != nil {
		logger.Error("[SSLYZE] Scan execution failed: %v", err)
		return response.InternalServerError(c, "SSLyze scan failed", err)
	}
	logger.Info("[SSLYZE] Scan completed successfully")

	if h.scanRepo != nil {
		_, dbErr := h.scanRepo.Insert(ctx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "sslyze",
			Target:    req.Target,
			Result:    result,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			logger.Error("[SSLYZE] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		logger.Debug("[SSLYZE] Database insert success")
	}

	if resMap, ok := result.(map[string]interface{}); ok {
		resMap["batch_id"] = req.BatchID
	}

	logger.Debug("[SSLYZE] Request completed successfully")
	return response.Success(c, "Scan completed", result)
}

// StartScanAsync initiates an async SSLyze scan
// @Summary Start SSLyze Scan (Async)
// @Description Start a SSLyze scan asynchronously. Returns task_id immediately.
// @Tags SSLyze
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param request body object{target=string,batch_id=string} true "Scan Request"
// @Success 200 {object} models.ScanTaskResponse
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /sslyze/scan/async [post]
func (h *SslyzeHandler) StartScanAsync(c *fiber.Ctx) error {
	logger.Debug("[SSLYZE_ASYNC] Received async scan request")

	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("[SSLYZE_ASYNC] Failed to parse request body: %v", err)
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
		logger.Warn("[SSLYZE_ASYNC] Batch ownership validation failed: %v", err)
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
		Tool:      "sslyze",
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
		err := service.RunSslyzeAsync(ctx, taskID, h.scanManager)
		if err != nil {
			logger.Error("[SSLYZE_ASYNC] Scan goroutine error: %v", err)
		}

		// Save to database if completed successfully
		if task, _ := h.scanManager.Get(taskID); task != nil && task.Status == models.StatusCompleted {
			if h.scanRepo != nil {
				dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer dbCancel()
				_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
					BatchID:   task.BatchID,
					Tool:      "sslyze",
					Target:    task.Target,
					Result:    task.Result,
					CreatedAt: time.Now().UTC(),
				})
				if dbErr != nil {
					logger.Error("[SSLYZE_ASYNC] Failed to save to database: %v", dbErr)
				} else {
					logger.Debug("[SSLYZE_ASYNC] Database insert success for task=%s", taskID)
				}
			}
		}
	}()

	logger.Info("[SSLYZE_ASYNC] Task created: task_id=%s, target=%s", taskID, req.Target)

	return response.Success(c, "scan started", fiber.Map{
		"task_id":  taskID,
		"status":   models.StatusRunning,
		"progress": 0,
	})
}
