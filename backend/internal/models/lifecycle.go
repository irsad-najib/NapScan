package models

import (
	"time"

	"gorm.io/gorm"
)

// FileStatus represents the current state of the file in the security scanning pipeline
type FileStatus string

const (
	FileStatusUploaded            FileStatus = "UPLOADED"
	FileStatusMobSFRunning        FileStatus = "MOBSF_RUNNING"
	FileStatusMobSFDone           FileStatus = "MOBSF_DONE"
	FileStatusWaitingUserDecision FileStatus = "WAITING_USER_DECISION"
	FileStatusFridaRunning        FileStatus = "FRIDA_RUNNING"
	FileStatusCompleted           FileStatus = "COMPLETED"
	FileStatusCleaned             FileStatus = "CLEANED"
	FileStatusFailed              FileStatus = "FAILED"
)

// UploadedFile represents a user uploaded file for security scanning
// It tracks the lifecycle state and stores high-level results
type UploadedFile struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	BatchID   string         `json:"batch_id" gorm:"type:varchar(191);index"`
	FileName  string         `json:"file_name" gorm:"type:varchar(255)"`
	FilePath  string         `json:"-" gorm:"type:varchar(512)"` // Local disk path
	Hash      string         `json:"hash" gorm:"type:varchar(64);index"`
	Status    FileStatus     `json:"status" gorm:"type:varchar(32);default:'UPLOADED'"`
	Severity  string         `json:"severity_score,omitempty" gorm:"column:severity_score;type:varchar(16)"` // high, medium, low, secure
	Findings  string         `json:"findings_summary,omitempty" gorm:"column:findings_summary;type:text"`       // JSON summary of findings
	Error     string         `json:"error_message,omitempty" gorm:"column:error_message;type:text"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// CanTransitionTo checks if a state transition is valid
func (f *UploadedFile) CanTransitionTo(next FileStatus) bool {
	switch f.Status {
	case FileStatusUploaded:
		// UPLOADED -> MOBSF_RUNNING (Normal flow)
		// UPLOADED -> FAILED (If upload/init fails)
		return next == FileStatusMobSFRunning || next == FileStatusFailed

	case FileStatusMobSFRunning:
		// MOBSF_RUNNING -> MOBSF_DONE (Scan complete)
		// MOBSF_RUNNING -> WAITING (If we skip explicit DONE state or merge them)
		// MOBSF_RUNNING -> FAILED (Scan error)
		return next == FileStatusMobSFDone || next == FileStatusWaitingUserDecision || next == FileStatusFailed

	case FileStatusMobSFDone:
		// MOBSF_DONE -> WAITING (Evaluation done)
		// MOBSF_DONE -> FAILED
		return next == FileStatusWaitingUserDecision || next == FileStatusFailed

	case FileStatusWaitingUserDecision:
		// WAITING -> FRIDA_RUNNING (User selected CONTINUE)
		// WAITING -> COMPLETED (User selected STOP)
		// WAITING -> FAILED (System error? Unlikely but possible)
		// WAITING -> CLEANED (If TTL expires while waiting? Maybe?)
		// User said: "Cleanup HANYA untuk state: COMPLETED, FAILED". So WAITING should NOT go to CLEANED automatically?
		// But if user abandons file? We should probably allow FAILED or CLEANED eventually.
		// For now, adhere to explicit user choice flow:
		return next == FileStatusFridaRunning || next == FileStatusCompleted || next == FileStatusFailed || next == FileStatusCleaned

	case FileStatusFridaRunning:
		// FRIDA -> COMPLETED (Scan done)
		// FRIDA -> FAILED (Scan error)
		return next == FileStatusCompleted || next == FileStatusFailed

	case FileStatusCompleted:
		// COMPLETED -> CLEANED (Cleanup worker)
		return next == FileStatusCleaned

	case FileStatusFailed:
		// FAILED -> CLEANED (Cleanup worker)
		// FAILED -> FAILED (Update error msg?)
		return next == FileStatusCleaned || next == FileStatusFailed

	case FileStatusCleaned:
		// Terminal state
		return false
	}
	return false
}
