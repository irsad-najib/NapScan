package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"napscan-be/internal/models"
	"napscan-be/pkg/parser"
	"strings"

	"gorm.io/gorm"
)

type RiskService struct {
	DB *gorm.DB
}

func NewRiskService(db *gorm.DB) *RiskService {
	return &RiskService{DB: db}
}

// AnalyzeBatch fetches all scan results for a batch, normalizes them, and calculates risk
func (s *RiskService) AnalyzeBatch(batchID string) (*models.ReportData, error) {
	var batch models.Batch
	if err := s.DB.Preload("ScanResults").Where("batch_id = ?", batchID).First(&batch).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch batch: %w", err)
	}

	reportData := &models.ReportData{
		BatchID:     batch.BatchID,
		GeneratedAt: batch.CreatedAt, // Or time.Now()
		// TargetInfo is derived from the first available target in scan results for now
	}

	var unifiedVulns []models.UnifiedVulnerability
	scanners := make(map[string]bool)

	// Process ScanResults
	for _, result := range batch.ScanResults {
		scanners[result.Tool] = true
		vulns := s.normalizeResult(result)
		unifiedVulns = append(unifiedVulns, vulns...)
		if reportData.TargetInfo == "" {
			reportData.TargetInfo = result.Target
		}
	}

	// Calculate Risk Summary
	reportData.Vulnerabilities = unifiedVulns
	reportData.RiskSummary = s.calculateRiskSummary(unifiedVulns)
	
	for tool := range scanners {
		reportData.ScannersUsed = append(reportData.ScannersUsed, tool)
	}
	
	reportData.ExecutiveSummary = s.generateExecutiveSummary(reportData.RiskSummary)

	return reportData, nil
}


// normalizeResult uses the standardized parsers from pkg/parser
func (s *RiskService) normalizeResult(result models.ScanResult) []models.UnifiedVulnerability {
	var vulns []models.UnifiedVulnerability
	
	if len(result.ResultRaw) == 0 {
		return vulns
	}

	var rawResult interface{}
	// Decode JSON to generic interface, handling JSONL (multiple objects)
	decoder := json.NewDecoder(bytes.NewReader(result.ResultRaw))
	decoder.UseNumber()

	var results []interface{}
	for {
		var obj interface{}
		if err := decoder.Decode(&obj); err == io.EOF {
			break
		} else if err != nil {
			break
		}
		results = append(results, obj)
	}

	if len(results) == 0 {
		return vulns
	}

	if len(results) == 1 {
		rawResult = results[0]
	} else {
		// If multiple objects, pass them as a slice (JSONL)
		rawResult = results
	}

	var p parser.ScannerParser

	// Map tool names to parsers
	switch strings.ToLower(result.Tool) {
	case "nmap":
		p = parser.NewNmapParser()
	case "nuclei":
		p = parser.NewNucleiParser()
	case "ffuf":
		p = parser.NewFFUFParser()
	case "openvas":
		p = parser.NewOpenVASParser()
	case "zap", "owasp-zap":
		p = parser.NewZAPParser()
	case "sslyze":
		p = parser.NewSSLyzeParser()
	case "mobsf":
		p = parser.NewMobSFParser()
	case "frida":
		p = parser.NewFridaParser()
	}

	if p != nil {
		parsed, err := p.Parse(rawResult)
		if err == nil && parsed != nil {
			for _, finding := range parsed.Findings {
				severity := strings.ToUpper(finding.Severity)
				
				vulns = append(vulns, models.UnifiedVulnerability{
					Title:            finding.Title,
					Description:      finding.Description,
					Severity:         severity,
					AffectedEndpoint: finding.Target,
					Scanner:          result.Tool,
					ToolRefID:        result.ID,
					// Estimate CVSS based on severity string since generic parser doesn't return CVSS
					CVSSScore: models.GetSeverityScore(models.NormalizeSeverity(severity)),
				})
			}
		}
	} else {
		// Generic fallback for unknown tools
		if genericMap, ok := rawResult.(map[string]interface{}); ok {
			if v, ok := genericMap["vulnerabilities"].([]interface{}); ok {
				for _, item := range v {
					if vm, ok := item.(map[string]interface{}); ok {
						vulns = append(vulns, models.UnifiedVulnerability{
							Title:            getString(vm, "title"),
							Description:      getString(vm, "description"),
							Severity:         getString(vm, "severity"),
							CVSSScore:        getFloat(vm, "cvss"),
							AffectedEndpoint: getString(vm, "endpoint"),
							Scanner:          result.Tool,
							ToolRefID:        result.ID,
						})
					}
				}
			}
		}
	}

	return vulns
}

func (s *RiskService) calculateRiskSummary(vulns []models.UnifiedVulnerability) models.RiskSummary {
	summary := models.RiskSummary{
		TotalVulnerabilities: len(vulns),
	}

	var totalScore float64

	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			summary.CriticalCount++
			totalScore += 10.0
		case "HIGH":
			summary.HighCount++
			totalScore += 7.0
		case "MEDIUM":
			summary.MediumCount++
			totalScore += 4.0
		case "LOW":
			summary.LowCount++
			totalScore += 1.0
		}
	}

	// Simple risk calculation algorithm
	// Scale 0-100 based on findings
	// Weighted: Critical * 10 + High * 5 + Medium * 2 + Low * 0.5
	weightedScore := (float64(summary.CriticalCount) * 10) + 
		(float64(summary.HighCount) * 5) + 
		(float64(summary.MediumCount) * 2) + 
		(float64(summary.LowCount) * 0.5)
	
	// Logistics curve or simple capping
	if weightedScore > 100 {
		weightedScore = 100
	}
	summary.OverallRiskScore = weightedScore

	if summary.OverallRiskScore >= 90 {
		summary.RiskLevel = "CRITICAL"
	} else if summary.OverallRiskScore >= 70 {
		summary.RiskLevel = "HIGH"
	} else if summary.OverallRiskScore >= 40 {
		summary.RiskLevel = "MEDIUM"
	} else if summary.OverallRiskScore > 0 {
		summary.RiskLevel = "LOW"
	} else {
		summary.RiskLevel = "SAFE"
	}

	return summary
}

func (s *RiskService) generateExecutiveSummary(summary models.RiskSummary) string {
	return fmt.Sprintf("Scan completed with a risk level of %s. Found %d vulnerabilities (%d Critical, %d High).", 
		summary.RiskLevel, summary.TotalVulnerabilities, summary.CriticalCount, summary.HighCount)
}

// Helpers
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0.0
}
