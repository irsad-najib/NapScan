package handler

import (
	"context"
	"net/url"
	"strings"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/service"
	"napscan-be/pkg/logger"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type ZapHandler struct {
	service      *service.ZapService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
	scanManager  *service.ScanManager
}

func NewZapHandler(s *service.ZapService, scanRepo repository.ScanResultRepository, batchService *service.BatchService, scanManager *service.ScanManager) *ZapHandler {
	return &ZapHandler{
		service:      s,
		scanRepo:     scanRepo,
		batchService: batchService,
		scanManager:  scanManager,
	}
}

// StartScan initiates a full ZAP scan (LEGACY SYNC)
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
	logger.Debug("[ZAP] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("[ZAP] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		logger.Warn("[ZAP] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	logger.Debug("[ZAP] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		logger.Warn("[ZAP] Batch ownership validation failed: %v", err)
		return err
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		logger.Warn("[ZAP] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}
	if !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
		target = "https://" + target
	}
	if _, err := url.ParseRequestURI(target); err != nil {
		logger.Warn("[ZAP] Invalid URL: %v", err)
		return response.BadRequest(c, "Invalid request URL", err)
	}

	logger.Info("[ZAP] Starting scan on target=%s", target)
	ctx, cancel := context.WithTimeout(c.Context(), 300*time.Second)
	defer cancel()

	result, err := h.service.ExecuteFullScan(ctx, target)
	if err != nil {
		logger.Error("[ZAP] Scan execution failed: %v", err)
		return response.InternalServerError(c, "ZAP scan failed", err)
	}
	logger.Info("[ZAP] Scan completed successfully")

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
			logger.Error("[ZAP] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		logger.Debug("[ZAP] Database insert success")
	}

	logger.Debug("[ZAP] Request completed successfully")
	return response.Success(c, "ZAP scan completed", result)
}

// StartScanAsync initiates an async ZAP scan
// @Summary Start ZAP Scan (Async)
// @Description Start a ZAP scan asynchronously. Returns task_id immediately.
// @Tags ZAP
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param request body object{target=string,batch_id=string} true "Scan Request"
// @Success 200 {object} models.ScanTaskResponse
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /zap/scan/async [post]
func (h *ZapHandler) StartScanAsync(c *fiber.Ctx) error {
	logger.Debug("[ZAP_ASYNC] Received async scan request")

	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("[ZAP_ASYNC] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		return response.BadRequest(c, "batch_id is required", nil)
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		return response.BadRequest(c, "target is required", nil)
	}

	// Add protocol if missing
	if !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
		target = "https://" + target
	}

	// Validate URL
	if _, err := url.ParseRequestURI(target); err != nil {
		logger.Warn("[ZAP_ASYNC] Invalid URL: %v", err)
		return response.BadRequest(c, "Invalid request URL", err)
	}

	// Validate batch ownership
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		logger.Warn("[ZAP_ASYNC] Batch ownership validation failed: %v", err)
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
		Target:    target,
		Tool:      "zap",
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
		err := service.RunZapAsync(ctx, taskID, h.scanManager)
		if err != nil {
			logger.Error("[ZAP_ASYNC] Scan goroutine error: %v", err)
		}

		// Save to database if completed successfully
		if task, _ := h.scanManager.Get(taskID); task != nil && task.Status == models.StatusCompleted {
			if h.scanRepo != nil {
				dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer dbCancel()
				_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
					BatchID:   task.BatchID,
					Tool:      "zap",
					Target:    task.Target,
					Result:    task.Result,
					CreatedAt: time.Now().UTC(),
				})
				if dbErr != nil {
					logger.Error("[ZAP_ASYNC] Failed to save to database: %v", dbErr)
				} else {
					logger.Debug("[ZAP_ASYNC] Database insert success for task=%s", taskID)
				}
			}
		}
	}()

	logger.Info("[ZAP_ASYNC] Task created: task_id=%s, target=%s", taskID, target)

	return response.Success(c, "scan started", fiber.Map{
		"task_id":  taskID,
		"status":   models.StatusRunning,
		"progress": 0,
	})
}
