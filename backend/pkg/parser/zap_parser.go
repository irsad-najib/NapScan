package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"sort"
	"strings"
)

type ZAPParser struct{}

func NewZAPParser() *ZAPParser {
	return &ZAPParser{}
}
var zapRiskMap = map[string]int{
	"informational": 10,
	"low":           30,
	"medium":        60,
	"high":          80,
}

func (p *ZAPParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	highestRisk := 0
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("zap result is not a map")
	}

	alertsRaw, ok := resultMap["alertsRaw"].(map[string]interface{})
	if !ok {
		return result, nil
	}

	alerts, ok := alertsRaw["alerts"].([]interface{})
	if !ok {
		return result, nil
	}

	for _, a := range alerts {
		alertMap, ok := a.(map[string]interface{})
		if !ok {
			continue
		}

		riskStr, _ := alertMap["risk"].(string)
		alertName, _ := alertMap["alert"].(string)
		url, _ := alertMap["url"].(string)

		description := fmt.Sprintf("%s on %s", alertName, url)

		sev := strings.ToLower(riskStr)

		result.Findings = append(result.Findings, Finding{
			Severity:    "info", // placeholder
			Title:       alertName,
			Description: description,
			Target:      url,
			RawData:     alertMap,
		})

		if risk, ok := zapRiskMap[sev]; ok {
			if risk > highestRisk {
				highestRisk = risk
			}
		}
	}

	result.Metadata["highest_risk"] = highestRisk
	return result, nil
}

func (p *ZAPParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "owasp-zap",
		Findings: []string{},
	}

	highestRisk := 0
	if v, ok := parsed.Metadata["highest_risk"].(int); ok {
		highestRisk = v
	}

	var allFindings []string
	for _, finding := range parsed.Findings {
		allFindings = append(allFindings, finding.Description)
	}

	finalSeverity := models.SeverityInfo
	switch {
	case highestRisk >= 75:
		finalSeverity = models.SeverityHigh
	case highestRisk >= 50:
		finalSeverity = models.SeverityMedium
	case highestRisk >= 30:
		finalSeverity = models.SeverityLow
	}

	detail.NormalizedSeverity = finalSeverity
	detail.Description = "Web application security issues detected by OWASP ZAP"

	sort.Strings(allFindings)
	detail.Findings = allFindings

	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1
	}

	detail.Score = float64(highestRisk)*10 + findingCount*2
	return detail, nil
}

func (p *ZAPParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
	aggregatedFindings := []string{}
	highestSeverity := models.SeverityInfo

	for _, scanResult := range rawResults {
		parsed, err := p.Parse(scanResult.Result)
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

		aggregatedFindings = append(aggregatedFindings, normalized.Findings...)
	}

	uniqueFindings := removeDuplicates(aggregatedFindings)
	sort.Strings(uniqueFindings)

	detail := &models.ScannerRiskDetail{
		Scanner:            "owasp-zap",
		NormalizedSeverity: highestSeverity,
		Description:        "Web application security issues detected by OWASP ZAP",
		Findings:           uniqueFindings,
	}

	baseScore := models.GetSeverityScore(highestSeverity)
	findingCount := float64(len(uniqueFindings))
	if findingCount == 0 {
		findingCount = 1
	}
	detail.Score = baseScore * findingCount

	return detail, nil
}
