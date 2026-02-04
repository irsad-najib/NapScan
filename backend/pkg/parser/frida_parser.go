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

var fridaRiskKeywords = map[string]int{
	"ssl unpin":        90,
	"unpinning":        90,
	"bypass":           85,
	"hooked":           80,
	"hook success":     80,
	"anti-debug":       85,
	"root bypass":      85,
	"jailbreak bypass": 85,
	"detected":         50,
	"found":            50,
}

func (p *FridaParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	highestRisk := 0
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("frida result is not a map")
	}

	// Unwrap "frida" key if present (persistence wrapper)
	if inner, ok := resultMap["frida"].(map[string]interface{}); ok {
		resultMap = inner
	}

	// 1. Check Status
	status, _ := resultMap["status"].(string)
	result.Metadata["status"] = status

	// 2. Parse Events (New Schema)
	if events, ok := resultMap["events"].([]interface{}); ok {
		for _, e := range events {
			if eMap, ok := e.(map[string]interface{}); ok {
				eventType, _ := eMap["event"].(string)
				dataMap, _ := eMap["data"].(map[string]interface{})

				// Construct description
				desc := fmt.Sprintf("Event: %s", eventType)
				if len(dataMap) > 0 {
					// simple serialization for desc
					desc += fmt.Sprintf(" Data: %v", dataMap)
				}

				// Check for specific interesting events
				if eventType == "hook_installed" {
					desc = "Hook installed"
					if cls, ok := dataMap["class"]; ok {
						desc += fmt.Sprintf(" on %v", cls)
					}
					if mjd, ok := dataMap["method"]; ok {
						desc += fmt.Sprintf(".%v", mjd)
					}
				}

				// Keyword matching for risk
				lowerDesc := strings.ToLower(desc)
				severity := "info"

				// Add "hook_installed" to check
				if strings.Contains(lowerDesc, "hook_installed") || strings.Contains(lowerDesc, "hook installed") {
					if 80 > highestRisk {
						highestRisk = 80
					}
					severity = "medium" // hooking is generally interesting/warning
				}

				for keyword, risk := range fridaRiskKeywords {
					if strings.Contains(lowerDesc, keyword) {
						if risk > highestRisk {
							highestRisk = risk
						}
						// crude mapping
						if risk >= 80 {
							severity = "high"
						} else if risk >= 50 {
							severity = "medium"
						}
						break
					}
				}

				result.Findings = append(result.Findings, Finding{
					Severity:    severity,
					Title:       fmt.Sprintf("Frida: %s", eventType),
					Description: desc,
					RawData:     eMap,
				})
			}
		}
	} else if logs, ok := resultMap["logs"].([]interface{}); ok {
		// Fallback to Old Schema (logs)
		for _, l := range logs {
			if logLine, ok := l.(string); ok {
				// Keyword matching for risk
				lowerLog := strings.ToLower(logLine)

				result.Findings = append(result.Findings, Finding{
					Severity:    "info", // placeholder
					Title:       "Frida Finding",
					Description: logLine,
					RawData:     logLine,
				})

				for keyword, risk := range fridaRiskKeywords {
					if strings.Contains(lowerLog, keyword) {
						if risk > highestRisk {
							highestRisk = risk
						}
						break
					}
				}
			}
		}
	}

	result.Metadata["highest_risk"] = highestRisk
	return result, nil
}

func (p *FridaParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "frida",
		Findings: []string{},
	}

	highestRisk := 0
	if v, ok := parsed.Metadata["highest_risk"].(int); ok {
		highestRisk = v
	}

	var allFindings []string
	for _, f := range parsed.Findings {
		allFindings = append(allFindings, f.Description)
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
	detail.Description = "Dynamic analysis findings from Frida"
	detail.Findings = allFindings

	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1
	}

	detail.Score = float64(highestRisk)*10 + findingCount*2
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
