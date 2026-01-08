package handler

import (
	"context"
	"time"

	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type OpenVASHandler struct {
	service *service.OpenVASService
}

func NewOpenVASHandler(s *service.OpenVASService) *OpenVASHandler {
	return &OpenVASHandler{service: s}
}

// GetVersion returns OpenVAS version
// @Summary Get OpenVAS Version
// @Description Check OpenVAS connectivity and version
// @Tags OpenVAS
// @Accept json
// @Produce xml
// @Success 200 {string} string "XML response"
// @Failure 500 {object} response.Response
// @Router /openvas/version [get]
func (h *OpenVASHandler) GetVersion(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
	defer cancel()

	ver, err := h.service.GetVersion(ctx)
	if err != nil {
		return response.InternalServerError(c, "Failed to get OpenVAS version", err)
	}
	c.Set("Content-Type", "application/xml")
	return c.SendString(ver)
}

// StartScan initiates an OpenVAS scan
// @Summary Start OpenVAS Scan
// @Description Create target, task, and start scan
// @Tags OpenVAS
// @Accept json
// @Produce json
// @Param body body object{target=string} true "Scan parameters"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /openvas/scan [post]
func (h *OpenVASHandler) StartScan(c *fiber.Ctx) error {
	var req struct {
		Target string `json:"target"`
	}

	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.Target == "" {
		return response.BadRequest(c, "Target is required", nil)
	}

	// No timeout context for start scan as it might take a bit (but creating task is fast usually)
	// Ideally we use a reasonably long timeout
	ctx, cancel := context.WithTimeout(c.Context(), 60*time.Second)
	defer cancel()

	result, err := h.service.StartScan(ctx, req.Target)
	if err != nil {
		return response.InternalServerError(c, "Failed to start OpenVAS scan", err)
	}

	return response.Success(c, "Scan started", result)
}

// GetTaskStatus returns task status in JSON
// @Summary Get Task Status
// @Description Get details of a task especially progress and report ID
// @Tags OpenVAS
// @Accept json
// @Produce json
// @Param taskId path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} response.Response
// @Router /openvas/task/{taskId}/status [get]
func (h *OpenVASHandler) GetTaskStatus(c *fiber.Ctx) error {
	taskID := c.Params("taskId")
	if taskID == "" {
		return response.BadRequest(c, "Task ID is required", nil)
	}

	ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
	defer cancel()

	status, err := h.service.GetTaskStatus(ctx, taskID)
	if err != nil {
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

	return c.JSON(res)
}

// GetScanReport returns report in JSON
// @Summary Get Scan Report
// @Description Get report details parsed as JSON
// @Tags OpenVAS
// @Accept json
// @Produce json
// @Param reportId path string true "Report ID"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} response.Response
// @Router /openvas/report/{reportId} [get]
func (h *OpenVASHandler) GetScanReport(c *fiber.Ctx) error {
	reportID := c.Params("reportId")
	if reportID == "" {
		return response.BadRequest(c, "Report ID is required", nil)
	}

	ctx, cancel := context.WithTimeout(c.Context(), 120*time.Second)
	defer cancel()

	report, err := h.service.GetScanReport(ctx, reportID)
	if err != nil {
		return response.InternalServerError(c, "Failed to get report", err)
	}
	
	return c.JSON(report)
}
