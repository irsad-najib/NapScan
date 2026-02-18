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
)

type OpenVASHandler struct {
	service      *service.OpenVASService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewOpenVASHandler(s *service.OpenVASService, scanRepo repository.ScanResultRepository, batchService *service.BatchService) *OpenVASHandler {
	return &OpenVASHandler{service: s, scanRepo: scanRepo, batchService: batchService}
}

// GetVersion returns OpenVAS version
// @Summary Get OpenVAS Version
// @Description Check OpenVAS connectivity and version
// @Tags OpenVAS
// @Security BearerAuth
// @Accept json
// @Produce xml
// @Success 200 {string} string "XML response"
// @Failure 500 {object} response.Response
// @Router /openvas/version [get]
func (h *OpenVASHandler) GetVersion(c *fiber.Ctx) error {
	logger.Info("[OPENVAS] GetVersion request")
	ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
	defer cancel()

	ver, err := h.service.GetVersion(ctx)
	if err != nil {
		logger.Error("[OPENVAS] Failed to get version: %v", err)
		return response.InternalServerError(c, "Failed to get OpenVAS version", err)
	}
	logger.Info("[OPENVAS] Version retrieved successfully")
	c.Set("Content-Type", "application/xml")
	return c.SendString(ver)
}

// StartScan initiates an OpenVAS scan
// @Summary Start OpenVAS Scan
// @Description Create target, task, and start scan
// @Tags OpenVAS
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body object{target=string,batch_id=string} true "Scan parameters"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /openvas/scan [post]
func (h *OpenVASHandler) StartScan(c *fiber.Ctx) error {
	logger.Info("[OPENVAS] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Warn("[OPENVAS] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		logger.Warn("[OPENVAS] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	logger.Info("[OPENVAS] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		logger.Warn("[OPENVAS] Batch ownership validation failed: %v", err)
		return err
	}

	if req.Target == "" {
		logger.Warn("[OPENVAS] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	// No timeout context for start scan as it might take a bit (but creating task is fast usually)
	// Ideally we use a reasonably long timeout
	logger.Info("[OPENVAS] Starting scan on target=%s", req.Target)
	ctx, cancel := context.WithTimeout(c.Context(), 60*time.Second)
	defer cancel()

	result, err := h.service.StartScan(ctx, req.Target, req.BatchID)
	if err != nil {
		logger.Error("[OPENVAS] Failed to start scan: %v", err)
		return response.InternalServerError(c, "Failed to start OpenVAS scan", err)
	}

	logger.Info("[OPENVAS] Scan started successfully")
	return response.Success(c, "Scan started", result)
}

// GetTaskStatus returns task status in JSON
// @Summary Get Task Status
// @Description Get details of a task especially progress and report ID
// @Tags OpenVAS
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param taskId path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} response.Response
// @Router /openvas/task/{taskId}/status [get]
func (h *OpenVASHandler) GetTaskStatus(c *fiber.Ctx) error {
	taskID := c.Params("taskId")
	if taskID == "" {
		logger.Warn("[OPENVAS] GetTaskStatus: Missing task ID")
		return response.BadRequest(c, "Task ID is required", nil)
	}

	logger.Info("[OPENVAS] GetTaskStatus for task_id=%s", taskID)
	ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
	defer cancel()

	status, err := h.service.GetTaskStatus(ctx, taskID)
	if err != nil {
		logger.Error("[OPENVAS] Failed to get task status: %v", err)
		return response.InternalServerError(c, "Failed to get task status", err)
	}

	// Transform to simple JSON
	res := map[string]interface{}{
		"status":   status.Status,
		"progress": status.Progress,
	}
	if status.LastReport.Report.ID != "" {
		res["reportId"] = status.LastReport.Report.ID
	}
	if status.BatchID != "" {
		res["batch_id"] = status.BatchID
	}

	logger.Info("[OPENVAS] Task status retrieved: status=%s progress=%s", status.Status, status.Progress)
	return c.JSON(res)
}

// GetScanReport returns report in JSON
// @Summary Get Scan Report
// @Description Get report details parsed as JSON
// @Tags OpenVAS
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param reportId path string true "Report ID"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} response.Response
// @Router /openvas/report/{reportId} [get]
func (h *OpenVASHandler) GetScanReport(c *fiber.Ctx) error {
	reportID := c.Params("reportId")
	if reportID == "" {
		logger.Warn("[OPENVAS] GetScanReport: Missing report ID")
		return response.BadRequest(c, "Report ID is required", nil)
	}

	logger.Info("[OPENVAS] GetScanReport for report_id=%s", reportID)
	ctx, cancel := context.WithTimeout(c.Context(), 120*time.Second)
	defer cancel()

	report, err := h.service.GetScanReport(ctx, reportID)
	if err != nil {
		logger.Error("[OPENVAS] Failed to get report: %v", err)
		return response.InternalServerError(c, "Failed to get report", err)
	}
	logger.Info("[OPENVAS] Report retrieved successfully")

	if h.scanRepo != nil {
		batchID := ""
		if report != nil {
			batchID = report.BatchID
		}
		if batchID != "" {
			dbCtx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
			defer cancel()
			_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
				BatchID:   batchID,
				Tool:      "openvas",
				Target:    "", // target not available from report endpoint
				Result:    report,
				CreatedAt: time.Now().UTC(),
			})
			if dbErr != nil {
				logger.Error("[OPENVAS] Failed to save to database: %v", dbErr)
				return response.InternalServerError(c, "Failed to save scan result", dbErr)
			}
			logger.Info("[OPENVAS] Database insert success")
		}
	}

	logger.Info("[OPENVAS] Request completed successfully")
	return c.JSON(report)
}
