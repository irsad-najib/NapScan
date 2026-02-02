package handler

import (
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ScanHandler handles scan control endpoints (stop, status, report)
type ScanHandler struct {
	scanManager *service.ScanManager
}

// NewScanHandler creates a new ScanHandler instance
func NewScanHandler(scanManager *service.ScanManager) *ScanHandler {
	return &ScanHandler{
		scanManager: scanManager,
	}
}

// StopScan stops a running scan task
// @Summary Stop Scan
// @Description Stops a running or pending scan task by task ID (works for all scanners)
// @Tags Scan Control
// @Security BearerAuth
// @Produce json
// @Param task_id path string true "Task ID"
// @Success 200 {object} models.ScanTaskResponse
// @Failure 404 {object} response.Response
// @Failure 409 {object} response.Response
// @Router /nmap/scan/{task_id}/stop [post]
// @Router /ffuf/scan/{task_id}/stop [post]
// @Router /sslyze/scan/{task_id}/stop [post]
// @Router /zap/scan/{task_id}/stop [post]
func (h *ScanHandler) StopScan(c *fiber.Ctx) error {
	taskID := c.Params("task_id")
	if taskID == "" {
		return response.Error(c, fiber.StatusBadRequest, "task_id is required", nil)
	}

	log.Printf("[SCAN_HANDLER] Stop request for task_id=%s", taskID)

	// Get task first to verify it exists
	task, err := h.scanManager.Get(taskID)
	if err != nil {
		log.Printf("[SCAN_HANDLER] Task not found: %v", err)
		return response.Error(c, fiber.StatusNotFound, "task not found", nil)
	}

	// Attempt to stop the task
	if err := h.scanManager.Stop(taskID); err != nil {
		log.Printf("[SCAN_HANDLER] Failed to stop task: %v", err)
		return response.Error(c, fiber.StatusConflict, err.Error(), nil)
	}

	// Get updated task
	task, _ = h.scanManager.Get(taskID)
	log.Printf("[SCAN_HANDLER] Task stopped successfully: task_id=%s", taskID)

	return response.Success(c, "scan stopped successfully", task.ToResponse())
}

// GetStatus returns the current status and progress of a scan task
// @Summary Get Scan Status
// @Description Returns the unified status and progress of a scan task (works for all scanners)
// @Tags Scan Control
// @Security BearerAuth
// @Produce json
// @Param task_id path string true "Task ID"
// @Success 200 {object} models.ScanTaskResponse
// @Failure 404 {object} response.Response
// @Router /nmap/scan/{task_id}/status [get]
// @Router /ffuf/scan/{task_id}/status [get]
// @Router /sslyze/scan/{task_id}/status [get]
// @Router /zap/scan/{task_id}/status [get]
func (h *ScanHandler) GetStatus(c *fiber.Ctx) error {
	taskID := c.Params("task_id")
	if taskID == "" {
		return response.Error(c, fiber.StatusBadRequest, "task_id is required", nil)
	}

	log.Printf("[SCAN_HANDLER] Status request for task_id=%s", taskID)

	task, err := h.scanManager.Get(taskID)
	if err != nil {
		log.Printf("[SCAN_HANDLER] Task not found: %v", err)
		return response.Error(c, fiber.StatusNotFound, "task not found", nil)
	}

	log.Printf("[SCAN_HANDLER] Status retrieved: task_id=%s, status=%s, progress=%d%%",
		taskID, task.Status, task.Progress)

	return response.Success(c, "status retrieved successfully", task.ToResponse())
}

// GetReport returns the scan report (only if completed)
// @Summary Get Scan Report
// @Description Returns the scan report/results. Only available when status is 'completed' (works for all scanners)
// @Tags Scan Control
// @Security BearerAuth
// @Produce json
// @Param task_id path string true "Task ID"
// @Success 200 {object} object{result=[]map[string]interface{}}
// @Failure 404 {object} response.Response
// @Failure 409 {object} response.Response
// @Router /nmap/scan/{task_id}/report [get]
// @Router /ffuf/scan/{task_id}/report [get]
// @Router /sslyze/scan/{task_id}/report [get]
// @Router /zap/scan/{task_id}/report [get]
func (h *ScanHandler) GetReport(c *fiber.Ctx) error {
	taskID := c.Params("task_id")
	if taskID == "" {
		return response.Error(c, fiber.StatusBadRequest, "task_id is required", nil)
	}

	log.Printf("[SCAN_HANDLER] Report request for task_id=%s", taskID)

	task, err := h.scanManager.Get(taskID)
	if err != nil {
		log.Printf("[SCAN_HANDLER] Task not found: %v", err)
		return response.Error(c, fiber.StatusNotFound, "task not found", nil)
	}

	// Only allow report access if scan is completed
	if task.Status != models.StatusCompleted {
		log.Printf("[SCAN_HANDLER] Report not available: task_id=%s, status=%s", taskID, task.Status)
		return response.Error(c, fiber.StatusConflict,
			"report not available: scan is not completed (current status: "+string(task.Status)+")", nil)
	}

	log.Printf("[SCAN_HANDLER] Report retrieved: task_id=%s", taskID)

	return response.Success(c, "report retrieved successfully", fiber.Map{
		"task_id": task.TaskID,
		"target":  task.Target,
		"result":  task.Result,
	})
}

// GetActiveScans returns all currently active scan tasks (from ScanManager and Nuclei)
// @Summary List Active Scans
// @Description Get a list of all currently running or pending scan tasks
// @Tags Scan Control
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.Response
// @Router /scan/active [get]
func (h *ScanHandler) GetActiveScans(c *fiber.Ctx) error {
	log.Printf("[SCAN_HANDLER] Fetching all active scans")

	activeScans := make([]models.ScanTaskResponse, 0)

	// 1. Get from ScanManager (Nmap, Zap, Ffuf, Sslyze)
	taskIDs := h.scanManager.List()
	for _, id := range taskIDs {
		task, err := h.scanManager.Get(id)
		if err == nil {
			activeScans = append(activeScans, task.ToResponse())
		}
	}

	// 2. Get from Nuclei Store
	nucleiTasks := GetAllActiveNucleiTasks()
	for _, t := range nucleiTasks {
		// Convert private ScanTask to models.ScanTaskResponse
		activeScans = append(activeScans, models.ScanTaskResponse{
			TaskID:    t.TaskID,
			Target:    t.Target,
			BatchID:   t.BatchID,
			Status:    models.ScanStatus(t.Status),
			Progress:  t.Progress,
			Tool:      "nuclei", // Explicitly set tool
			UserID:    t.UserID,
			StartedAt: t.StartedAt.Format(time.RFC3339),
			UpdatedAt: t.UpdatedAt.Format(time.RFC3339),
		})
	}

	return response.Success(c, "active scans retrieved", activeScans)
}
