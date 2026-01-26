package risk

import (
	"napscan-be/internal/models"
	"testing"
)

func TestCalculateScannerScore(t *testing.T) {
	tests := []struct {
		name     string
		detail   models.ScannerRiskDetail
		expected float64
	}{
		{
			name: "Nmap High Severity",
			detail: models.ScannerRiskDetail{
				Scanner:            "nmap",
				NormalizedSeverity: models.SeverityHigh,
				Findings:           []string{"Port 22", "Port 80", "Port 445"}, // 3 findings
			},
			// Score = 7.5 (High) * 3 (Count) * 1.0 (Weight) = 22.5
			expected: 22.5,
		},
		{
			name: "Nuclei Critical Severity",
			detail: models.ScannerRiskDetail{
				Scanner:            "nuclei",
				NormalizedSeverity: models.SeverityCritical,
				Findings:           []string{"Log4Shell", "SQL Injection"}, // 2 findings
			},
			// Score = 10.0 (Critical) * 2 (Count) * 1.2 (Weight) = 24.0
			expected: 24.0,
		},
		{
			name: "Info Severity",
			detail: models.ScannerRiskDetail{
				Scanner:            "ffuf",
				NormalizedSeverity: models.SeverityInfo,
				Findings:           []string{"Header found"},
			},
			// Score = 0.0 * 1 * 1.0 = 0.0
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateScannerScore(&tt.detail)
			if score != tt.expected {
				t.Errorf("CalculateScannerScore() = %v, want %v", score, tt.expected)
			}
		})
	}
}

func TestCalculateBatchRisk(t *testing.T) {
	details := []models.ScannerRiskDetail{
		{
			Scanner:            "nmap",
			NormalizedSeverity: models.SeverityMedium,
			Findings:           []string{"Port 80", "Port 443"},
			// Score = 5.0 * 2 * 1.0 = 10.0
		},
		{
			Scanner:            "nuclei",
			NormalizedSeverity: models.SeverityHigh,
			Findings:           []string{"CVE-2023-1234"},
			// Score = 7.5 * 1 * 1.2 = 9.0
		},
	}

	batchRisk := CalculateBatchRisk("test-batch", details)

	// Total = 10.0 + 9.0 = 19.0
	if batchRisk.RiskScore != 19.0 {
		t.Errorf("Batch RiskScore = %v, want 19.0", batchRisk.RiskScore)
	}

	// 19.0 is LOW (0-25)
	if batchRisk.RiskLevel != models.SeverityLow {
		t.Errorf("Batch RiskLevel = %v, want LOW", batchRisk.RiskLevel)
	}
}

func TestCalculateBatchRiskCap(t *testing.T) {
	details := []models.ScannerRiskDetail{
		{
			Scanner:            "nuclei",
			NormalizedSeverity: models.SeverityCritical,
			Findings:           make([]string, 10), // 10 critical findings
			// Score = 10.0 * 10 * 1.2 = 120.0 -> Capped at 100.0
		},
	}

	batchRisk := CalculateBatchRisk("test-batch-cap", details)

	if batchRisk.RiskScore != 100.0 {
		t.Errorf("Batch RiskScore = %v, want 100.0 (capped)", batchRisk.RiskScore)
	}
	
	if batchRisk.RiskLevel != models.SeverityCritical {
		t.Errorf("Batch RiskLevel = %v, want CRITICAL", batchRisk.RiskLevel)
	}
}
