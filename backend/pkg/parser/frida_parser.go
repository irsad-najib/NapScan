package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"strings"
)

type FridaParser struct{}

func NewFridaParser() *FridaParser {
	return &FridaParser{}
}

func (p *FridaParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("frida result is not a map")
	}

	// 1. Check Status
	status, _ := resultMap["status"].(string)
	result.Metadata["status"] = status

	// 2. Parse Logs for key events
	if logs, ok := resultMap["logs"].([]interface{}); ok {
		for _, l := range logs {
			if logLine, ok := l.(string); ok {
				// Keyword matching for risk
				lowerLog := strings.ToLower(logLine)
				
				if strings.Contains(lowerLog, "bypass") || strings.Contains(lowerLog, "unpinning") {
					result.Findings = append(result.Findings, Finding{
						Severity:    "high",
						Title:       "Security Control Bypassed",
						Description: logLine,
						RawData:     logLine,
					})
				} else if strings.Contains(lowerLog, "detect") || strings.Contains(lowerLog, "found") {
					// "Root detected" -> High risk mostly
					result.Findings = append(result.Findings, Finding{
						Severity:    "medium",
						Title:       "Security Check Triggered",
						Description: logLine,
						RawData:     logLine,
					})
				} else if strings.Contains(lowerLog, "fail") || strings.Contains(lowerLog, "error") {
					// Operational issue or maybe check failed?
					// Usually implies app crashed or detection worked (good for blue, bad for red team perspective?)
					// Assuming risk engine measures "Risk to the App". 
					// If App Detects Frida -> It has defenses -> Lower Risk?
					// OR Risk Engine measures "Vulnerabilities".
					// If Frida Bypasses SSL -> Vulnerability -> High Risk.
					// If Root Detected -> Defense working -> Low Risk (Good).
					// BUT usually "Root Detected" in a report means "We found it has root detection". A pen test report usually lists defenses.
					// Let's assume finding = vulnerability.
					// So "Bypass" is the main finding.
				}
			}
		}
	}

	result.Metadata["total_findings"] = len(result.Findings)
	return result, nil
}

func (p *FridaParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "frida",
		Findings: []string{},
	}

	highestSeverity := models.SeverityInfo
	var allFindings []string

	for _, finding := range parsed.Findings {
		normalized := models.NormalizeSeverity(finding.Severity)
		if models.GetSeverityScore(normalized) > models.GetSeverityScore(highestSeverity) {
			highestSeverity = normalized
		}
		allFindings = append(allFindings, finding.Description)
	}

	detail.NormalizedSeverity = highestSeverity
	detail.Description = "Dynamic analysis findings from Frida"
	detail.Findings = allFindings

	// Calculate Score: High if Bypasses found
	baseScore := models.GetSeverityScore(highestSeverity)
	findingCount := float64(len(allFindings))
	if findingCount == 0 { findingCount = 1 }
	
	detail.Score = baseScore * findingCount
	
	// Check status
	if parsed.Metadata["status"] == "failed" {
		// If script failed, maybe risk is unknown? 
		// Or assume info
	}

	return detail, nil
}

func (p *FridaParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
	if len(rawResults) == 0 {
		return nil, fmt.Errorf("no results")
	}

	detail := &models.ScannerRiskDetail{
		Scanner:  "frida",
		Findings: []string{},
	}
	highestSeverity := models.SeverityInfo
	var allFindings []string
	var maxScore float64 = 0.0

	for _, res := range rawResults {
		parsed, err := p.Parse(res.Result)
		if err != nil {
			continue
		}
		normalized, err := p.Normalize(parsed)
		if err != nil {
			continue
		}

		if models.GetSeverityScore(normalized.NormalizedSeverity) > models.GetSeverityScore(highestSeverity) {
			highestSeverity = normalized.NormalizedSeverity
		}
		allFindings = append(allFindings, normalized.Findings...)
		if normalized.Score > maxScore {
			maxScore = normalized.Score
		}
	}

	detail.NormalizedSeverity = highestSeverity
	detail.Findings = allFindings
	detail.Score = maxScore
	detail.Description = fmt.Sprintf("Dynamic analysis findings (%d items)", len(allFindings))

	return detail, nil
}
