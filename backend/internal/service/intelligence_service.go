package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"napscan-be/internal/models"
	"napscan-be/pkg/parser"
	"napscan-be/pkg/risk"

	"gorm.io/gorm"
)

type IntelligenceService struct {
	db          *gorm.DB
	cveService  *CVEService
	cpeService  *CPEService
	cweService  *CWEService
	cvssService *CVSSService
}

func NewIntelligenceService(db *gorm.DB, cve *CVEService, cpe *CPEService, cwe *CWEService, cvss *CVSSService) *IntelligenceService {
	return &IntelligenceService{
		db:          db,
		cveService:  cve,
		cpeService:  cpe,
		cweService:  cwe,
		cvssService: cvss,
	}
}

// ProcessScanResult parses raw output and processes all findings
func (s *IntelligenceService) ProcessScanResult(ctx context.Context, scanID, tenantID, tool string, rawResult interface{}) error {
	p := risk.GetParser(tool)
	if p == nil {
		return fmt.Errorf("no parser found for tool: %s", tool)
	}

	parsed, err := p.Parse(rawResult)
	if err != nil {
		return fmt.Errorf("failed to parse scan result: %w", err)
	}

	for _, finding := range parsed.Findings {
		_, err := s.ProcessFinding(ctx, scanID, tenantID, finding)
		if err != nil {
			log.Printf("[Intelligence] Failed to process finding: %v", err)
			// Continue processing others
		}
	}

	return nil
}

// ProcessFinding takes a structured finding, classifies it, enriches it, scores it, and saves it.
func (s *IntelligenceService) ProcessFinding(ctx context.Context, scanID, tenantID string, finding parser.Finding) (*models.DetectedFinding, error) {
	// 1. Classification
	detected := &models.DetectedFinding{
		ScanID:    scanID,
		TenantID:  tenantID,
		RawData:   mustMarshal(finding.RawData),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Scanner:   finding.Source,
	}

	// Use extracted fields
	severityStr := finding.Severity
	refID := finding.ReferenceID

	// Detection Logic
	// Case 1: CVE-Based
	if strings.HasPrefix(strings.ToUpper(refID), "CVE-") {
		detected.VulnType = models.FindingTypeCVE
		detected.ReferenceID = refID

		// Enrich from CVE Service
		cveData, err := s.cveService.GetCVE(ctx, refID)
		if err == nil && cveData != nil {
			detected.CVSSScore = cveData.CVSSScore
			detected.CVSSVector = cveData.CVSSVector
			detected.Severity = cveData.Severity
			detected.Description = cveData.Description
			detected.Title = cveData.CVEID // Use CVE ID as title
		} else {
			// Fallback if NVD fetch fails
			log.Printf("[Intelligence] Failed to fetch CVE %s: %v", refID, err)
			normalized := models.NormalizeSeverity(severityStr)
			detected.Severity = string(normalized)
			detected.Title = finding.Title
			detected.Description = finding.Description
		}
	} else if strings.HasPrefix(strings.ToUpper(refID), "CWE-") {
		// Case 2: Weakness (CWE)
		detected.VulnType = models.FindingTypeCWE
		detected.ReferenceID = refID
		detected.Title = finding.Title
		detected.Description = finding.Description

		normalized := models.NormalizeSeverity(severityStr)
		detected.Severity = string(normalized)
		detected.CVSSScore = models.GetSeverityScore(normalized) // Fallback
	} else {
		// Case 3: Exposure / Generic
		detected.VulnType = models.FindingTypeExposure
		detected.ReferenceID = refID // Might be empty or internal ID
		detected.Title = finding.Title
		detected.Description = finding.Description

		normalized := models.NormalizeSeverity(severityStr)
		detected.Severity = string(normalized)
		detected.CVSSScore = models.GetSeverityScore(normalized)
	}

	// Finalize struct
	if detected.CVSSVector == "" {
		detected.CVSSVector = generateFallbackVector(detected.Severity)
	}

	// 2. Persist
	if err := s.db.Create(detected).Error; err != nil {
		return nil, fmt.Errorf("failed to save finding: %w", err)
	}

	return detected, nil
}

// Helpers

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func extractCVE(info map[string]interface{}) string {
	// Nuclei puts classification.cve-id usually
	if class, ok := info["classification"].(map[string]interface{}); ok {
		if cves, ok := class["cve-id"]; ok {
			// Could be string or []interface{} (list of CVEs)
			if s, ok := cves.(string); ok {
				return s
			}
			if list, ok := cves.([]interface{}); ok && len(list) > 0 {
				if s, ok := list[0].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func extractCWE(info map[string]interface{}) string {
	if class, ok := info["classification"].(map[string]interface{}); ok {
		if cwes, ok := class["cwe-id"]; ok {
			if s, ok := cwes.(string); ok {
				return s
			}
			if list, ok := cwes.([]interface{}); ok && len(list) > 0 {
				if s, ok := list[0].(string); ok {
					return s
				}
			}
		}
	}
	// Fallback to tags?
	return ""
}

func generateFallbackVector(severity string) string {
	// Simple mapping for fallback
	switch strings.ToLower(severity) {
	case "critical":
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	case "high":
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	case "medium":
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
	case "low":
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
	default:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
	}
}
