package handler

import (
	"context"
	"database/sql"
	"time"

	"napscan-be/internal/aggregator"
	"napscan-be/internal/orchestrator"
	"napscan-be/internal/repository"
	"napscan-be/internal/scanner"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ScanHandler handles scan-related HTTP requests
type ScanHandler struct {
	orchestrator *orchestrator.BatchOrchestrator
	aggregator   *aggregator.ReportAggregator
	batchRepo    *repository.BatchRepository
}

// NewScanHandler creates a new scan handler
func NewScanHandler(db *sql.DB, registry scanner.ScannerRegistry) *ScanHandler {
	batchRepo := repository.NewBatchRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	
	return &ScanHandler{
		orchestrator: orchestrator.NewBatchOrchestrator(registry, batchRepo, vulnRepo),
		aggregator:   aggregator.NewReportAggregator(batchRepo, vulnRepo),
		batchRepo:    batchRepo,
	}
}

// CreateScanRequest represents the request to create a new scan
type CreateScanRequest struct {
	Target    string                 `json:"target" validate:"required"`
	ScanType  string                 `json:"scan_type" validate:"required,oneof=all single custom"`
	ToolNames []string               `json:"tool_names,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
	Timeout   int                    `json:"timeout,omitempty"` // In minutes
}

// CreateScanResponse represents the response after creating a scan
type CreateScanResponse struct {
	BatchID    string    `json:"batch_id"`
	Status     string    `json:"status"`
	Message    string    `json:"message"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateScan handles POST /api/scans
// @Summary Create new security scan
// @Description Creates a new batch scan with specified tools and target
// @Tags Scans
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateScanRequest true "Scan configuration"
// @Success 202 {object} CreateScanResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scans [post]
func (h *ScanHandler) CreateScan(c *fiber.Ctx) error {
	// Get user ID from context (set by auth middleware)
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}
	
	// Parse request body
	var req CreateScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}
	
	// Generate batch ID
	batchID := uuid.New().String()
	
	// Convert scan type
	var scanType orchestrator.ScanType
	switch req.ScanType {
	case "all":
		scanType = orchestrator.ScanTypeAll
	case "single":
		scanType = orchestrator.ScanTypeSingle
	case "custom":
		scanType = orchestrator.ScanTypeCustom
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid scan_type. Must be 'all', 'single', or 'custom'",
		})
	}
	
	// Set default timeout
	timeout := 15 * time.Minute
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Minute
	}
	
	// Create batch request
	batchReq := &orchestrator.BatchRequest{
		UserID:    userID,
		BatchID:   batchID,
		Target:    req.Target,
		ScanType:  scanType,
		ToolNames: req.ToolNames,
		Options:   req.Options,
		Timeout:   timeout,
	}
	
	// Execute batch asynchronously
	go func() {
		ctx := context.Background()
		_, err := h.orchestrator.ExecuteBatch(ctx, batchReq)
		if err != nil {
			// Log error but don't fail the request
			// The batch status will show as failed in the database
			// TODO: Implement proper error notification
		}
	}()
	
	return c.Status(fiber.StatusAccepted).JSON(CreateScanResponse{
		BatchID:   batchID,
		Status:    "processing",
		Message:   "Scan batch created successfully. Use the batch_id to check progress.",
		CreatedAt: time.Now(),
	})
}

// GetBatchStatus handles GET /api/scans/:batchId
// @Summary Get batch scan status
// @Description Retrieves the current status of a batch scan
// @Tags Scans
// @Produce json
// @Security BearerAuth
// @Param batchId path string true "Batch ID"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scans/{batchId} [get]
func (h *ScanHandler) GetBatchStatus(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}
	
	batchID := c.Params("batchId")
	if batchID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Batch ID is required",
		})
	}
	
	// Get batch from database
	batch, err := h.batchRepo.GetBatchByID(c.Context(), batchID, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve batch",
		})
	}
	
	if batch == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Batch not found",
		})
	}
	
	// Get scan jobs
	jobs, err := h.batchRepo.GetScanJobsByBatchID(c.Context(), batch.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve scan jobs",
		})
	}
	
	// Build response
	jobStatus := make([]map[string]interface{}, 0, len(jobs))
	for _, job := range jobs {
		var duration int64
		if job.DurationMs != nil {
			duration = *job.DurationMs
		}
		
		jobStatus = append(jobStatus, map[string]interface{}{
			"tool_name":  job.ToolName,
			"status":     job.Status,
			"start_time": job.StartTime,
			"end_time":   job.EndTime,
			"duration_ms": duration,
			"error":      job.ErrorMessage,
		})
	}
	
	return c.JSON(fiber.Map{
		"batch_id":           batch.BatchID,
		"status":             batch.Status,
		"target":             batch.Target,
		"expected_jobs":      batch.ExpectedJobCount,
		"completed_jobs":     batch.CompletedJobCount,
		"failed_jobs":        batch.FailedJobCount,
		"created_at":         batch.CreatedAt,
		"updated_at":         batch.UpdatedAt,
		"completed_at":       batch.CompletedAt,
		"jobs":               jobStatus,
	})
}

// GetBatchReport handles GET /api/scans/:batchId/report
// @Summary Get comprehensive scan report
// @Description Retrieves a detailed security report for a completed batch scan
// @Tags Scans
// @Produce json
// @Security BearerAuth
// @Param batchId path string true "Batch ID"
// @Success 200 {object} aggregator.UnifiedReport
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scans/{batchId}/report [get]
func (h *ScanHandler) GetBatchReport(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}
	
	batchIDStr := c.Params("batchId")
	if batchIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Batch ID is required",
		})
	}
	
	// Get batch to verify it exists and belongs to user
	batch, err := h.batchRepo.GetBatchByID(c.Context(), batchIDStr, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve batch",
		})
	}
	
	if batch == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Batch not found",
		})
	}
	
	// Check if batch is completed
	if batch.Status != "completed" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Batch scan is not completed yet",
			"status": batch.Status,
		})
	}
	
	// Generate comprehensive report
	report, err := h.aggregator.GenerateReport(c.Context(), batch.ID, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate report",
		})
	}
	
	return c.JSON(report)
}

// ListBatches handles GET /api/scans
// @Summary List user's scan batches
// @Description Retrieves a paginated list of scan batches for the authenticated user
// @Tags Scans
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Number of results per page" default(10)
// @Param offset query int false "Pagination offset" default(0)
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scans [get]
func (h *ScanHandler) ListBatches(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}
	
	// Parse pagination parameters
	limit := c.QueryInt("limit", 10)
	offset := c.QueryInt("offset", 0)
	
	if limit > 100 {
		limit = 100 // Max limit
	}
	
	// Get batches
	batches, err := h.batchRepo.ListBatchesByUser(c.Context(), userID, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve batches",
		})
	}
	
	// Build response
	results := make([]map[string]interface{}, 0, len(batches))
	for _, batch := range batches {
		results = append(results, map[string]interface{}{
			"batch_id":       batch.BatchID,
			"target":         batch.Target,
			"status":         batch.Status,
			"expected_jobs":  batch.ExpectedJobCount,
			"completed_jobs": batch.CompletedJobCount,
			"failed_jobs":    batch.FailedJobCount,
			"created_at":     batch.CreatedAt,
			"completed_at":   batch.CompletedAt,
		})
	}
	
	return c.JSON(fiber.Map{
		"batches": results,
		"limit":   limit,
		"offset":  offset,
		"count":   len(results),
	})
}
