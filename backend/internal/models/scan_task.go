package models

import (
	"context"
	"encoding/json"
	"time"
)

// ScanStatus represents the status of a scan task
type ScanStatus string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusStopped   ScanStatus = "stopped"
	StatusFailed    ScanStatus = "failed"
	StatusCompleted ScanStatus = "completed"
)

// ScanTask represents a single scan task with all its metadata
type ScanTask struct {
	BatchID   string          `json:"batch_id"`
	TaskID    string          `json:"task_id"`
	UserID    string          `json:"user_id"`
	Target    string          `json:"target"`
	Tool      string          `json:"tool"` // "nmap", "zap", etc
	Status    ScanStatus      `json:"status"`
	Progress  int             `json:"progress"`
	Error     *string         `json:"error"`
	ResultRaw json.RawMessage `json:"result_raw" swaggertype:"object"`
	Result    interface{}     `json:"result,omitempty"` // Flexible result type
	StartedAt time.Time       `json:"started_at"`
	UpdatedAt time.Time       `json:"updated_at"`

	// Internal fields (not exported to JSON)
	Cancel context.CancelFunc `json:"-"`
}

// ScanTaskResponse is the unified response format for all scan endpoints
type ScanTaskResponse struct {
	BatchID   string      `json:"batch_id"`
	TaskID    string      `json:"task_id"`
	UserID    string      `json:"user_id"`
	Target    string      `json:"target"`
	Tool      string      `json:"tool"`
	Status    ScanStatus  `json:"status"`
	Progress  int         `json:"progress"`
	Error     *string     `json:"error"`
	Result    interface{} `json:"result"`
	StartedAt string      `json:"started_at"` // RFC3339 format
	UpdatedAt string      `json:"updated_at"` // RFC3339 format
}

// ToResponse converts ScanTask to ScanTaskResponse with RFC3339 timestamps
func (t *ScanTask) ToResponse() ScanTaskResponse {
	return ScanTaskResponse{
		BatchID:   t.BatchID,
		TaskID:    t.TaskID,
		UserID:    t.UserID,
		Target:    t.Target,
		Tool:      t.Tool,
		Status:    t.Status,
		Progress:  t.Progress,
		Error:     t.Error,
		Result:    t.Result,
		StartedAt: t.StartedAt.Format(time.RFC3339),
		UpdatedAt: t.UpdatedAt.Format(time.RFC3339),
	}
}
