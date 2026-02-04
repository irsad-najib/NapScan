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
	highestRisk := 0.0
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("mobsf result is not a map")
	}

	// Unwrap "mobsf" key if present (persistence wrapper)
	if inner, ok := resultMap["mobsf"].(map[string]interface{}); ok {
		resultMap = inner
	}

	// 1. Extract Score
	if score, ok := resultMap["security_score"].(float64); ok {
		// MobSF: 100 = aman, 0 = buruk
		result.Metadata["mobsf_risk"] = 100.0 - score
	}
	if avgCVSS, ok := resultMap["average_cvss"].(float64); ok {
		result.Metadata["average_cvss"] = avgCVSS
	}

	// 2. Parse Findings (New Schema: findings are at root under "high", "warning", etc.)
	// Structure: { "findings": { "high": [...], "warning": [...], ... } }
	if findingsMap, ok := resultMap["findings"].(map[string]interface{}); ok {
		// Iterate over severity keys
		for sevKey, indList := range findingsMap {
			// standard keys: high, warning, info, secure, hotspot
			if findingsList, ok := indList.([]interface{}); ok {
				for _, fItem := range findingsList {
					if fMap, ok := fItem.(map[string]interface{}); ok {
						// Determine severity
						severity := "info"
						switch sevKey {
						case "high", "critical":
							severity = "high"
						case "warning":
							severity = "medium"
						case "secure":
							severity = "info"
						}

						// Extract details
						title := "MobSF Finding"
						if t, ok := fMap["title"].(string); ok {
							title = t
						}

						desc := ""
						if d, ok := fMap["description"].(string); ok {
							desc = d
						}

						result.Findings = append(result.Findings, Finding{
							Severity:    severity,
							Title:       title,
							Description: desc,
							RawData:     fMap,
						})

						// Update highest risk
						switch severity {
						case "high":
							if 80 > highestRisk {
								highestRisk = 80
							}
						case "medium":
							if 60 > highestRisk {
								highestRisk = 60
							}
						}
					}
				}
			}
		}
	} else if codeAnalysis, ok := resultMap["code_analysis"].(map[string]interface{}); ok {
		// Fallback to OLD Schema (code_analysis)
		if findings, ok := codeAnalysis["findings"].(map[string]interface{}); ok {
			for key, f := range findings {
				if fMap, ok := f.(map[string]interface{}); ok {
					// MobSF severity: warning, high, info
					severity := "info"
					if sev, ok := fMap["severity"].(string); ok {
						switch sev {
						case "high", "critical":
							severity = "high"
						case "warning":
							severity = "medium"
						}
					}

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
					switch severity {
					case "high":
						if 80 > highestRisk {
							highestRisk = 80
						}
					case "medium":
						if 60 > highestRisk {
							highestRisk = 60
						}
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

	result.Metadata["highest_risk"] = highestRisk
	return result, nil
}

func (p *MobSFParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "mobsf",
		Findings: []string{},
	}

	var highestRisk float64 = 0

	if v, ok := parsed.Metadata["mobsf_risk"].(float64); ok {
		highestRisk = v
	} else if v, ok := parsed.Metadata["highest_risk"].(float64); ok {
		highestRisk = v
	}

	var allFindings []string
	for _, f := range parsed.Findings {
		allFindings = append(allFindings, f.Title)
	}

	finalSeverity := models.SeverityInfo
	switch {
	case highestRisk >= 90:
		finalSeverity = models.SeverityCritical
	case highestRisk >= 75:
		finalSeverity = models.SeverityHigh
	case highestRisk >= 50:
		finalSeverity = models.SeverityMedium
	case highestRisk >= 30:
		finalSeverity = models.SeverityLow
	}

	detail.NormalizedSeverity = finalSeverity
	detail.Description = "Static analysis findings from MobSF"
	detail.Findings = allFindings

	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1
	}

	detail.Score = highestRisk*10 + findingCount*2
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
		if normalized.Score > detail.Score {
			detail.Score = normalized.Score
		}
	}

	detail.NormalizedSeverity = highestSeverity
	detail.Description = "Static analysis findings from MobSF"
	detail.Findings = allFindings

	return detail, nil
}
