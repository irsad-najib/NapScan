package models

import (
	"bytes"
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
	Target    string    `json:"target" gorm:"type:varchar(255)"`
	ResultRaw []byte    `json:"-" gorm:"column:result"`
	Result    interface{} `json:"result" gorm:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// ScanResultSummary represents a cleansed version of the scan result
// This is used for API responses to avoid sending massive raw JSON
type ScanResultSummary struct {
	ID        uint        `json:"id"`
	Tool      string      `json:"tool"`
	Target    string      `json:"target"`
	Summary   interface{} `json:"summary"` // Dynamic summary based on tool
	CreatedAt time.Time   `json:"created_at"`
}

func (sr *ScanResult) BeforeSave(tx *gorm.DB) (err error) {
	if sr.Result != nil {
		sr.ResultRaw, err = json.Marshal(sr.Result)
	}
	return
}

func (sr *ScanResult) AfterFind(tx *gorm.DB) (err error) {
	if sr.ResultRaw != nil {
		decoder := json.NewDecoder(bytes.NewReader(sr.ResultRaw))
		decoder.UseNumber()
		err = decoder.Decode(&sr.Result)
	}
	return
}
