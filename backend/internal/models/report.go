package models

import "time"

// UnifiedVulnerability represents a normalized vulnerability finding from any tool
type UnifiedVulnerability struct {
	Title            string  `json:"title"`
	Description      string  `json:"description"`
	Severity         string  `json:"severity"` // LOW | MEDIUM | HIGH | CRITICAL
	CVSSScore        float64 `json:"cvss_score"`
	AffectedEndpoint string  `json:"affected_endpoint"`
	Evidence         string  `json:"evidence"`
	Recommendation   string  `json:"recommendation"`
	Scanner          string  `json:"scanner"`
	ToolRefID        uint    `json:"tool_ref_id"` // Reference to original scan_result ID
}

// RiskSummary represents the aggregated risk data for a batch
type RiskSummary struct {
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	CriticalCount        int     `json:"critical_count"`
	HighCount            int     `json:"high_count"`
	MediumCount          int     `json:"medium_count"`
	LowCount             int     `json:"low_count"`
	InfoCount            int     `json:"info_count"`
	OverallRiskScore     float64 `json:"overall_risk_score"` // 0-100
	RiskLevel            string  `json:"risk_level"`         // Safe, Low, Medium, High, Critical
}

// ReportData contains all necessary data to generate the PDF report
type ReportData struct {
	BatchID          string                 `json:"batch_id"`
	GeneratedAt      time.Time              `json:"generated_at"`
	TargetInfo       string                 `json:"target_info"`
	RiskSummary      RiskSummary            `json:"risk_summary"`
	Vulnerabilities  []UnifiedVulnerability `json:"vulnerabilities"`
	ScannersUsed     []string               `json:"scanners_used"`
	ScanDuration     string                 `json:"scan_duration"`
	ExecutiveSummary string                 `json:"executive_summary"`
}
