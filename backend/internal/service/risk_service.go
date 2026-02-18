package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/pkg/parser"
	"strings"

	"gorm.io/gorm"
)

type RiskService struct {
	DB          *gorm.DB
	FindingRepo repository.FindingRepository
}

func NewRiskService(db *gorm.DB, findingRepo repository.FindingRepository) *RiskService {
	return &RiskService{
		DB:          db,
		FindingRepo: findingRepo,
	}
}

// AnalyzeBatch fetches all scan results for a batch, normalizes them, and calculates risk
func (s *RiskService) AnalyzeBatch(batchID string) (*models.ReportData, error) {
	var batch models.Batch
	if err := s.DB.Preload("ScanResults").Preload("UploadedFiles").Where("batch_id = ?", batchID).First(&batch).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch batch: %w", err)
	}

	reportData := &models.ReportData{
		BatchID:     batch.BatchID,
		GeneratedAt: batch.CreatedAt, // Or time.Now()
		// TargetInfo is derived from the first available target in scan results for now
	}

	// 0. Inject Mobile Scans (APK) from AnalysisResultRaw
	// If AnalysisResultRaw exists, we check for MobSF/Frida results and treat them as ScanResults in memory
	if len(batch.AnalysisResultRaw) > 0 {
		var analysisMap map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(batch.AnalysisResultRaw))
		decoder.UseNumber()
		if err := decoder.Decode(&analysisMap); err == nil {

			// Determine Target Name (APK Filename)
			target := "MobileApp.apk" // Fallback
			if len(batch.UploadedFiles) > 0 {
				target = batch.UploadedFiles[0].FileName
			}

			// Check MobSF
			if mobsf, ok := analysisMap["mobsf"]; ok {
				batch.ScanResults = append(batch.ScanResults, models.ScanResult{
					BatchID:   batchID,
					Tool:      "mobsf",
					Target:    target,
					Result:    mobsf,
					CreatedAt: batch.CreatedAt,
				})
			} else if _, ok := analysisMap["security_score"]; ok {
				// Fallback: If no "mobsf" key but has "security_score", assume the whole map is MobSF
				batch.ScanResults = append(batch.ScanResults, models.ScanResult{
					BatchID:   batchID,
					Tool:      "mobsf",
					Target:    target,
					Result:    analysisMap,
					CreatedAt: batch.CreatedAt,
				})
			}

			// Check Frida
			if frida, ok := analysisMap["frida"]; ok {
				batch.ScanResults = append(batch.ScanResults, models.ScanResult{
					BatchID:   batchID,
					Tool:      "frida",
					Target:    target,
					Result:    frida,
					CreatedAt: batch.CreatedAt,
				})
			} else if _, ok := analysisMap["logs"]; ok {
				// Fallback: If no "frida" key but has "logs" (array), assume the whole map is Frida
				batch.ScanResults = append(batch.ScanResults, models.ScanResult{
					BatchID:   batchID,
					Tool:      "frida",
					Target:    target,
					Result:    analysisMap,
					CreatedAt: batch.CreatedAt,
				})
			}
		}
	}

	var unifiedVulns []models.UnifiedVulnerability
	scanners := make(map[string]bool)

	// 1. Try to fetch normalized findings from repository (New Architecture)
	storedFindings, err := s.FindingRepo.GetByBatchID(context.Background(), batchID)

	// Deduplication Map: Key = Title + Scanner + AffectedEndpoint
	uniqueFindings := make(map[string]models.UnifiedVulnerability)

	if err == nil && len(storedFindings) > 0 {
		for _, f := range storedFindings {
			scanners[f.Scanner] = true

			// Create a unique key
			key := fmt.Sprintf("%s|%s|%s", f.Title, f.Scanner, "Target")

			if _, exists := uniqueFindings[key]; !exists {
				uniqueFindings[key] = models.UnifiedVulnerability{
					Title:            f.Title,
					Description:      f.Description,
					Severity:         f.Severity,
					CVSSScore:        f.CVSSScore, // Use specific score from Intelligence
					AffectedEndpoint: "Target",    // Finding struct doesn't have target yet? add if needed or rely on metadata
					Scanner:          f.Scanner,
					ToolRefID:        0, // Not strictly needed for stats
				}
			}
		}
		// If we have stored findings, we might still want to get Target info from ScanResults
		if len(batch.ScanResults) > 0 {
			reportData.TargetInfo = batch.ScanResults[0].Target
		}
	} else {
		// 2. Fallback: Process raw ScanResults (Legacy / Ad-hoc)
		for _, result := range batch.ScanResults {
			scanners[result.Tool] = true
			vulns := s.normalizeResult(result)

			for _, v := range vulns {
				key := fmt.Sprintf("%s|%s|%s", v.Title, v.Scanner, v.AffectedEndpoint)
				if _, exists := uniqueFindings[key]; !exists {
					uniqueFindings[key] = v
				}
			}

			if reportData.TargetInfo == "" {
				reportData.TargetInfo = result.Target
			}
		}
	}

	// Convert Map to Slice
	for _, v := range uniqueFindings {
		unifiedVulns = append(unifiedVulns, v)
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
				// Basic normalization for report
				// Using helper to map raw severity to score
				normSev := models.NormalizeSeverity(severity)
				score := models.GetSeverityScore(normSev)

				vulns = append(vulns, models.UnifiedVulnerability{
					Title:            finding.Title,
					Description:      finding.Description,
					Severity:         severity,
					AffectedEndpoint: finding.Target,
					Scanner:          result.Tool,
					ToolRefID:        result.ID,
					CVSSScore:        score,
				})
			}
		}
	} else {
		// Generic fallback for unknown tools in report
		// (Simplified for now to avoid build errors with unknown struct fields)
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
		case "INFO", "INFORMATIONAL":
			summary.InfoCount++
			// Info does not contribute to risk score
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
