package service

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"napscan-be/internal/models"
)

// ScanManager is a global, thread-safe manager for all scan tasks
type ScanManager struct {
	tasks map[string]*models.ScanTask
	mu    sync.RWMutex
}

// NewScanManager creates a new ScanManager instance
func NewScanManager() *ScanManager {
	return &ScanManager{
		tasks: make(map[string]*models.ScanTask),
	}
}

// Register adds a new scan task to the manager
func (sm *ScanManager) Register(task *models.ScanTask) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.tasks[task.TaskID] = task
}

// Get retrieves a scan task by ID
func (sm *ScanManager) Get(taskID string) (*models.ScanTask, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	task, ok := sm.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}
	return task, nil
}

// UpdateProgress updates the progress and status of a scan task
func (sm *ScanManager) UpdateProgress(taskID string, progress int, status models.ScanStatus) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	task, ok := sm.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	// Only update if not already in a final state (stopped, failed, completed)
	if task.Status == models.StatusStopped || task.Status == models.StatusFailed || task.Status == models.StatusCompleted {
		return nil
	}

	// Clamp progress between 0 and 100
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}

	task.Progress = progress
	task.Status = status
	task.UpdatedAt = time.Now()
	return nil
}

// Fail marks a scan task as failed with an error message
func (sm *ScanManager) Fail(taskID string, err error) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	task, ok := sm.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	// Only fail if not already in a final state
	if task.Status == models.StatusStopped || task.Status == models.StatusFailed || task.Status == models.StatusCompleted {
		return nil
	}

	errMsg := err.Error()
	task.Error = &errMsg
	task.Status = models.StatusFailed
	task.UpdatedAt = time.Now()
	return nil
}

// Complete marks a scan task as completed with results
func (sm *ScanManager) Complete(taskID string, result interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	task, ok := sm.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	// Only complete if not already in a final state
	if task.Status == models.StatusStopped || task.Status == models.StatusFailed || task.Status == models.StatusCompleted {
		return nil
	}

	// Handle json.RawMessage or []byte directly
	if raw, ok := result.(json.RawMessage); ok {
		task.ResultRaw = raw
	} else if rawBytes, ok := result.([]byte); ok {
		task.ResultRaw = json.RawMessage(rawBytes)
	} else {
		// Fallback for logic still passing maps/structs
		// We marshal it to store as Raw
		if b, err := json.Marshal(result); err == nil {
			task.ResultRaw = json.RawMessage(b)
		}
		
		// ALSO populate Result so GetReport works!
		task.Result = result
	}

	task.Status = models.StatusCompleted
	task.Progress = 100
	task.UpdatedAt = time.Now()
	return nil
}

// Stop cancels a running scan task
func (sm *ScanManager) Stop(taskID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	task, ok := sm.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	// Only stop if running or pending
	if task.Status != models.StatusRunning && task.Status != models.StatusPending {
		return fmt.Errorf("task cannot be stopped: status is %s", task.Status)
	}

	// Cancel the context if available
	if task.Cancel != nil {
		task.Cancel()
	}

	task.Status = models.StatusStopped
	task.UpdatedAt = time.Now()
	return nil
}

// Delete removes a task from the manager (for cleanup)
func (sm *ScanManager) Delete(taskID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.tasks, taskID)
}

// List returns all task IDs (for debugging/monitoring)
func (sm *ScanManager) List() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	ids := make([]string, 0, len(sm.tasks))
	for id := range sm.tasks {
		ids = append(ids, id)
	}
	return ids
}
