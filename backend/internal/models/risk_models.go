package models

import "time"

// NormalizedSeverity represents the unified severity scale across all scanners
type NormalizedSeverity string

const (
	SeverityInfo     NormalizedSeverity = "INFO"
	SeverityLow      NormalizedSeverity = "LOW"
	SeverityMedium   NormalizedSeverity = "MEDIUM"
	SeverityHigh     NormalizedSeverity = "HIGH"
	SeverityCritical NormalizedSeverity = "CRITICAL"
)

// ScannerRiskDetail represents the normalized risk output from a single scanner
type ScannerRiskDetail struct {
	Scanner            string             `json:"scanner"`
	NormalizedSeverity NormalizedSeverity `json:"normalized_severity"`
	Score              float64            `json:"score"`
	Description        string             `json:"description"`
	Findings           []string           `json:"findings"`
}

// BatchRiskResponse represents the complete risk assessment for a batch
type BatchRiskResponse struct {
	BatchID    string               `json:"batch_id"`
	RiskScore  float64              `json:"risk_score"`
	RiskLevel  NormalizedSeverity   `json:"risk_level"`
	RiskDetail []ScannerRiskDetail  `json:"risk_detail"`
}

// BatchDetailResponse represents the complete batch information including risk
type BatchDetailResponse struct {
	BatchID     string               `json:"batch_id"`
	UserID      string               `json:"user_id"`
	Status      string               `json:"status"`
	CreatedAt   time.Time            `json:"created_at"`
	Target      string               `json:"target"`
	RiskScore   float64              `json:"risk_score"`
	RiskLevel   NormalizedSeverity  `json:"risk_level"`
	RiskDetail  []ScannerRiskDetail `json:"risk_detail"`
	ScanResults []ScanResultSummary `json:"scan_results"`
}

// NormalizeSeverity converts scanner-specific severity strings to NormalizedSeverity
func NormalizeSeverity(severity string) NormalizedSeverity {
	switch severity {
	case "critical", "Critical", "CRITICAL":
		return SeverityCritical
	case "high", "High", "HIGH":
		return SeverityHigh
	case "medium", "Medium", "MEDIUM", "warning", "Warning", "WARNING":
		return SeverityMedium
	case "low", "Low", "LOW":
		return SeverityLow
	case "info", "Info", "INFO", "informational", "Informational", "INFORMATIONAL":
		return SeverityInfo
	default:
		return SeverityInfo // Default to INFO for unknown severities
	}
}

// GetSeverityScore returns the numeric score for a severity level
func GetSeverityScore(severity NormalizedSeverity) float64 {
	switch severity {
	case SeverityCritical:
		return 10.0
	case SeverityHigh:
		return 7.5
	case SeverityMedium:
		return 5.0
	case SeverityLow:
		return 2.5
	case SeverityInfo:
		return 0.0
	default:
		return 0.0
	}
}

// ClassifyRiskLevel converts a numeric risk score to a severity level
func ClassifyRiskLevel(score float64) NormalizedSeverity {
	if score >= 76.0 {
		return SeverityCritical
	} else if score >= 51.0 {
		return SeverityHigh
	} else if score >= 26.0 {
		return SeverityMedium
	} else if score > 0.0 {
		return SeverityLow
	}
	return SeverityInfo
}
