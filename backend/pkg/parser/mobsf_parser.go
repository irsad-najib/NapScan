package parser

import (
	"fmt"
	"napscan-be/internal/models"
)

type MobSFParser struct{}

func NewMobSFParser() *MobSFParser {
	return &MobSFParser{}
}

func (p *MobSFParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("mobsf result is not a map")
	}

	// 1. Extract Score
	if score, ok := resultMap["security_score"].(float64); ok {
		result.Metadata["security_score"] = score
	}
	if avgCVSS, ok := resultMap["average_cvss"].(float64); ok {
		result.Metadata["average_cvss"] = avgCVSS
	}

	// 2. Parse Code Analysis for High/Critical issues
	if codeAnalysis, ok := resultMap["code_analysis"].(map[string]interface{}); ok {
		if findings, ok := codeAnalysis["findings"].(map[string]interface{}); ok {
			for key, f := range findings {
				if fMap, ok := f.(map[string]interface{}); ok {
					// MobSF severity: warning, high, info
					severity := "info"
					if sev, ok := fMap["severity"].(string); ok {
						if sev == "high" || sev == "critical" {
							severity = "high"
						} else if sev == "warning" {
							severity = "medium"
						}
					}

					// Only add meaningful findings
					if severity != "info" {
						title := key
						if metadata, ok := fMap["metadata"].(map[string]interface{}); ok {
							if desc, ok := metadata["description"].(string); ok {
								title = desc
							}
						}

						result.Findings = append(result.Findings, Finding{
							Severity:    severity,
							Title:       title,
							Description: fmt.Sprintf("Found in file: %v", key), // key is often filename
							RawData:     fMap,
						})
					}
				}
			}
		}
	}

	// 3. Parse Permissions
	if permissions, ok := resultMap["permissions"].(map[string]interface{}); ok {
		dangerousCount := 0
		for _, permData := range permissions {
			if pMap, ok := permData.(map[string]interface{}); ok {
				if status, ok := pMap["status"].(string); ok && status == "dangerous" {
					dangerousCount++
				}
			}
		}
		if dangerousCount > 0 {
			result.Findings = append(result.Findings, Finding{
				Severity:    "medium",
				Title:       "Dangerous Permissions",
				Description: fmt.Sprintf("Found %d dangerous permissions", dangerousCount),
			})
		}
	}

	result.Metadata["total_findings"] = len(result.Findings)
	return result, nil
}

func (p *MobSFParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "mobsf",
		Findings: []string{},
	}

	highestSeverity := models.SeverityInfo
	var allFindings []string

	for _, finding := range parsed.Findings {
		normalized := models.NormalizeSeverity(finding.Severity)
		if models.GetSeverityScore(normalized) > models.GetSeverityScore(highestSeverity) {
			highestSeverity = normalized
		}
		allFindings = append(allFindings, finding.Title)
	}

	detail.NormalizedSeverity = highestSeverity
	detail.Description = "Static analysis findings from MobSF"
	detail.Findings = allFindings

	// Calculate Score based on MobSF Security Score (0-100) or findings
	// If MobSF gives a score, use 100 - score as risk? Or parsed metadata?
	// MobSF 100 is secure, 0 is insecure (usually). So Risk = 100 - Score.
	if score, ok := parsed.Metadata["security_score"].(float64); ok {
		detail.Score = 100.0 - score
		if detail.Score < 0 {
			detail.Score = 0
		}
	} else {
		// Fallback to finding-based
		baseScore := models.GetSeverityScore(highestSeverity)
		findingCount := float64(len(allFindings))
		if findingCount == 0 { findingCount = 1 }
		detail.Score = baseScore * findingCount
	}

	return detail, nil
}

func (p *MobSFParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
	if len(rawResults) == 0 {
		return nil, fmt.Errorf("no results")
	}

	// For APKs, we might have multiple files, but typically one primary result.
	// We'll process the first valid one or aggregate.
	// Let's aggregate findings.
	
	detail := &models.ScannerRiskDetail{
		Scanner:  "mobsf",
		Findings: []string{},
	}
	highestSeverity := models.SeverityInfo
	var allFindings []string
	var lowestScore float64 = 100.0 // Assume perfect score start

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
		
		// Track worst score
		if normalized.Score > 0 && (100-normalized.Score) < lowestScore {
			// Normalize logic: My Normalize returns Risk Score (0-100 badness).
			// If normalized.Score is high, that's bad.
			// So we just sum or take max risk.
		}
		if normalized.Score > detail.Score {
			detail.Score = normalized.Score
		}
	}

	detail.NormalizedSeverity = highestSeverity
	detail.Description = "Static analysis findings from MobSF"
	detail.Findings = allFindings

	return detail, nil
}
