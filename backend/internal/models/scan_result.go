package models

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// ScanResult stores the raw output of a tool scan.
// For SQL backends, this maps to the "scan_results" table.
type ScanResult struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	BatchID   string    `json:"batch_id" gorm:"type:varchar(191);index"`
	Tool      string    `json:"tool" gorm:"type:varchar(64)"`
	Target    string          `json:"target" gorm:"type:varchar(255)"`
	ResultRaw json.RawMessage `json:"result" gorm:"column:result" swaggertype:"object"`
	Result    interface{}     `json:"-" gorm:"-"`
	CreatedAt time.Time       `json:"created_at"`
}

// ScanResultSummary represents a cleansed version of the scan result
// This is used for API responses to avoid sending massive raw JSON
type ScanResultSummary struct {
	ID        uint        `json:"id"`
	Tool      string      `json:"tool"`
	Target    string          `json:"target"`
	Summary   interface{}     `json:"summary"` // Dynamic summary based on tool
	Result    json.RawMessage `json:"result,omitempty" swaggertype:"object"` // Raw result
	CreatedAt time.Time       `json:"created_at"`
}

func (sr *ScanResult) BeforeSave(tx *gorm.DB) (err error) {
	if sr.Result != nil && sr.ResultRaw == nil {
		sr.ResultRaw, err = json.Marshal(sr.Result)
	}
	return
}

func (sr *ScanResult) AfterFind(tx *gorm.DB) (err error) {
	// Disable auto-decoding
	return
}
