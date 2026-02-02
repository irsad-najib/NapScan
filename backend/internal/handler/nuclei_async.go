package handler

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"napscan-be/internal/models"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// TaskStatus represents the status of an async scan task
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
)

// ScanTask represents an async scan task
type ScanTask struct {
	TaskID    string                   `json:"task_id"`
	Target    string                   `json:"target"`
	BatchID   string                   `json:"batch_id"`
	Status    TaskStatus               `json:"status"`
	Progress  int                      `json:"progress"` // 0-100
	Result    []map[string]interface{} `json:"result,omitempty"`
	Error     string                   `json:"error,omitempty"`
	StartedAt time.Time                `json:"started_at"`
	UpdatedAt time.Time                `json:"updated_at"`
	UserID    string                   `json:"user_id"`
}

// TaskStore manages async scan tasks in memory
type TaskStore struct {
	mu    sync.RWMutex
	tasks map[string]*ScanTask
	ttl   time.Duration
}

var nucleiTaskStore = &TaskStore{
	tasks: make(map[string]*ScanTask),
	ttl:   30 * time.Minute, // Tasks expire after 30 minutes
}

func (ts *TaskStore) Create(userID, target, batchID string) *ScanTask {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	task := &ScanTask{
		TaskID:    uuid.New().String(),
		Target:    target,
		BatchID:   batchID,
		Status:    TaskStatusPending,
		Progress:  0,
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		UserID:    userID,
	}

	ts.tasks[task.TaskID] = task

	// Cleanup old tasks
	go ts.cleanup()

	return task
}

func (ts *TaskStore) Get(taskID string) (*ScanTask, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	task, ok := ts.tasks[taskID]
	return task, ok
}

func (ts *TaskStore) Update(taskID string, updateFn func(*ScanTask)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if task, ok := ts.tasks[taskID]; ok {
		updateFn(task)
		task.UpdatedAt = time.Now()
	}
}

func (ts *TaskStore) Delete(taskID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tasks, taskID)
}

func (ts *TaskStore) cleanup() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	for id, task := range ts.tasks {
		if now.Sub(task.UpdatedAt) > ts.ttl {
			log.Printf("[NUCLEI_TASK] Cleaning up expired task: %s", id)
			delete(ts.tasks, id)
		}
	}
}

// GetAllActiveNucleiTasks returns all active tasks from the store
func GetAllActiveNucleiTasks() []*ScanTask {
	nucleiTaskStore.mu.RLock()
	defer nucleiTaskStore.mu.RUnlock()

	tasks := make([]*ScanTask, 0, len(nucleiTaskStore.tasks))
	for _, task := range nucleiTaskStore.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

// StartScanAsync initiates an async Nuclei scan
// @Summary Start Nuclei Scan (Async)
// @Description Start a Nuclei scan asynchronously. Returns task_id immediately.
// @Tags Nuclei
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param target body object{target=string,batch_id=string} true "Target URL or Hostname"
// @Success 202 {object} object{task_id=string,status=string,message=string}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /nuclei/scan/async [post]
func (h *NucleiHandler) StartScanAsync(c *fiber.Ctx) error {
	log.Printf("[NUCLEI_ASYNC] Received async scan request")

	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		log.Printf("[NUCLEI_ASYNC] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		log.Printf("[NUCLEI_ASYNC] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	log.Printf("[NUCLEI_ASYNC] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[NUCLEI_ASYNC] Batch ownership validation failed: %v", err)
		return err
	}

	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		log.Printf("[NUCLEI_ASYNC] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	// Get user ID
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[NUCLEI_ASYNC] User not authenticated")
		return response.Unauthorized(c, "User not authenticated")
	}

	// Create task
	task := nucleiTaskStore.Create(userID, req.Target, req.BatchID)
	log.Printf("[NUCLEI_ASYNC] Created task: %s for target=%s", task.TaskID, req.Target)

	// Run scan in background
	go h.runAsyncScan(task)

	// Return task ID immediately
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"task_id": task.TaskID,
		"status":  task.Status,
		"message": "Scan started. Use /nuclei/scan/async/{task_id} to check status",
		"target":  req.Target,
	})
}

// GetTaskStatus returns the status of an async scan task
// @Summary Get Nuclei Scan Task Status
// @Description Get the status and progress of an async Nuclei scan
// @Tags Nuclei
// @Security BearerAuth
// @Produce json
// @Param taskId path string true "Task ID"
// @Success 200 {object} ScanTask
// @Failure 404 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /nuclei/scan/async/{taskId} [get]
func (h *NucleiHandler) GetTaskStatus(c *fiber.Ctx) error {
	taskID := c.Params("taskId")
	if taskID == "" {
		return response.BadRequest(c, "Task ID is required", nil)
	}

	task, ok := nucleiTaskStore.Get(taskID)
	if !ok {
		return response.Error(c, fiber.StatusNotFound, "Task not found", nil)
	}

	// Verify ownership
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "User not authenticated")
	}

	if task.UserID != userID {
		log.Printf("[NUCLEI_ASYNC] Access denied: user=%s tried to access task=%s owned by %s",
			userID, taskID, task.UserID)
		return response.Error(c, fiber.StatusForbidden, "Access denied", nil)
	}

	// Return task info without full results
	taskInfo := fiber.Map{
		"task_id":    task.TaskID,
		"target":     task.Target,
		"batch_id":   task.BatchID,
		"status":     task.Status,
		"progress":   task.Progress,
		"started_at": task.StartedAt,
		"updated_at": task.UpdatedAt,
	}

	if task.Status == TaskStatusFailed {
		taskInfo["error"] = task.Error
	}

	if task.Status == TaskStatusCompleted {
		taskInfo["result_count"] = len(task.Result)
		taskInfo["message"] = "Scan completed. Use /nuclei/scan/async/{taskId}/result to get results"
	}

	return c.JSON(taskInfo)
}

// GetTaskResult returns the result of a completed scan
// @Summary Get Nuclei Scan Result
// @Description Get the full result of a completed Nuclei scan
// @Tags Nuclei
// @Security BearerAuth
// @Produce json
// @Param taskId path string true "Task ID"
// @Param compact query boolean false "Return compact summary (default: true)"
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /nuclei/scan/async/{taskId}/result [get]
func (h *NucleiHandler) GetTaskResult(c *fiber.Ctx) error {
	taskID := c.Params("taskId")
	if taskID == "" {
		return response.BadRequest(c, "Task ID is required", nil)
	}

	task, ok := nucleiTaskStore.Get(taskID)
	if !ok {
		return response.Error(c, fiber.StatusNotFound, "Task not found", nil)
	}

	// Verify ownership
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "User not authenticated")
	}

	if task.UserID != userID {
		return response.Error(c, fiber.StatusForbidden, "Access denied", nil)
	}

	if task.Status != TaskStatusCompleted {
		return response.Error(c, fiber.StatusBadRequest,
			"Scan not completed yet. Status: "+string(task.Status), nil)
	}

	// Check if compact mode is requested
	compact := c.Query("compact", "true")
	isCompact := strings.ToLower(strings.TrimSpace(compact)) == "true"

	var payload fiber.Map

	if isCompact {
		log.Printf("[NUCLEI_ASYNC] Building compact summary for task=%s", taskID)
		summary := buildNucleiSummary(task.Result)
		payload = fiber.Map{
			"task_id":  task.TaskID,
			"target":   task.Target,
			"summary":  summary,
			"batch_id": task.BatchID,
			"compact":  true,
		}
	} else {
		const maxFullResults = 100
		displayResults := task.Result
		truncated := false

		if len(task.Result) > maxFullResults {
			displayResults = task.Result[:maxFullResults]
			truncated = true
		}

		payload = fiber.Map{
			"task_id":        task.TaskID,
			"target":         task.Target,
			"results":        displayResults,
			"batch_id":       task.BatchID,
			"compact":        false,
			"total_count":    len(task.Result),
			"returned_count": len(displayResults),
			"truncated":      truncated,
		}
	}

	return response.Success(c, "Scan result retrieved", payload)
}

// runAsyncScan executes the scan in background
func (h *NucleiHandler) runAsyncScan(task *ScanTask) {
	log.Printf("[NUCLEI_ASYNC] Starting background scan for task=%s target=%s",
		task.TaskID, task.Target)

	// Update status to running
	nucleiTaskStore.Update(task.TaskID, func(t *ScanTask) {
		t.Status = TaskStatusRunning
		t.Progress = 10
	})

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second) // 10 minutes
	defer cancel()

	// Execute scan
	results, err := h.service.ExecuteScan(ctx, task.Target)

	if err != nil {
		log.Printf("[NUCLEI_ASYNC] Scan failed for task=%s: %v", task.TaskID, err)
		nucleiTaskStore.Update(task.TaskID, func(t *ScanTask) {
			t.Status = TaskStatusFailed
			t.Error = err.Error()
			t.Progress = 0
		})
		return
	}

	log.Printf("[NUCLEI_ASYNC] Scan completed for task=%s with %d findings",
		task.TaskID, len(results))

	// Update task with results
	nucleiTaskStore.Update(task.TaskID, func(t *ScanTask) {
		t.Status = TaskStatusCompleted
		t.Progress = 100
		t.Result = results
	})

	// Save to database
	if h.scanRepo != nil {
		summary := buildNucleiSummary(results)
		payload := fiber.Map{
			"target":   task.Target,
			"summary":  summary,
			"batch_id": task.BatchID,
		}

		dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
			BatchID:   task.BatchID,
			Tool:      "nuclei",
			Target:    task.Target,
			Result:    payload,
			CreatedAt: time.Now().UTC(),
		})

		if dbErr != nil {
			log.Printf("[NUCLEI_ASYNC] Failed to save to database for task=%s: %v",
				task.TaskID, dbErr)
		} else {
			log.Printf("[NUCLEI_ASYNC] Database insert success for task=%s", task.TaskID)
		}
	}

	// Log response size
	if jsonBytes, err := json.Marshal(results); err == nil {
		log.Printf("[NUCLEI_ASYNC] Result size for task=%s: %d bytes (%.2f KB)",
			task.TaskID, len(jsonBytes), float64(len(jsonBytes))/1024)
	}
}
