package models

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// VulnerabilityProfile defines internal mappings for non-CVE findings (Weakness-Based).
// Maps to "vulnerability_profiles" table.
type VulnerabilityProfile struct {
	InternalCode      string         `json:"internal_code" gorm:"primaryKey;type:varchar(128)"`
	Name              string         `json:"name" gorm:"type:varchar(255)"`
	CWEID             string         `json:"cwe_id" gorm:"type:varchar(64);index"`
	DefaultCVSSVector string         `json:"default_cvss_vector" gorm:"type:varchar(255)"`
	DefaultCVSSScore  float64        `json:"default_cvss_score" gorm:"type:decimal(4,1)"`
	Severity          string         `json:"severity" gorm:"type:varchar(32)"`
	Description       string         `json:"description" gorm:"type:text"`
	Recommendation    string         `json:"recommendation" gorm:"type:text"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `json:"-" gorm:"index"`
}

// TableName overrides the table name to `vulnerability_profiles`
func (VulnerabilityProfile) TableName() string {
	return "vulnerability_profiles"
}

// FindingType defines the classification of a finding
type FindingType string

const (
	FindingTypeCVE      FindingType = "CVE"
	FindingTypeCPE      FindingType = "CPE"
	FindingTypeCWE      FindingType = "CWE"
	FindingTypeExposure FindingType = "EXPOSURE"
)

// DetectedFinding represents a normalized security finding from any tool.
// This replaces the raw `scan_results` usage for reporting.
// Maps to "detected_findings" table.
type DetectedFinding struct {
	ID       uint        `json:"id" gorm:"primaryKey"`
	ScanID   string      `json:"scan_id" gorm:"type:varchar(191);index"` // Could map to BatchID or TaskID
	TenantID string      `json:"tenant_id" gorm:"type:varchar(191);index"`
	VulnType FindingType `json:"vuln_type" gorm:"type:varchar(32);index"` // CVE, CPE, CWE, EXPOSURE

	// ReferenceID links to the specific definition (CVE-ID, CPE-URI, or InternalCode)
	ReferenceID string `json:"reference_id" gorm:"type:varchar(255);index"`

	Title       string `json:"title" gorm:"type:varchar(255)"`
	Description string `json:"description" gorm:"type:text"`
	Scanner     string `json:"scanner" gorm:"type:varchar(50)"`

	CVSSScore  float64 `json:"cvss_score" gorm:"type:decimal(4,1)"`
	CVSSVector string  `json:"cvss_vector" gorm:"type:varchar(255)"`
	Severity   string  `json:"severity" gorm:"type:varchar(32)"` // Critical, High, Medium, Low, None

	RawData json.RawMessage `json:"raw_data" gorm:"type:longtext"` // Original tool output snippet

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// TableName overrides the table name to `detected_findings`
func (DetectedFinding) TableName() string {
	return "detected_findings"
}
