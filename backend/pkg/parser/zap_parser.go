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

func (p *ZAPParser) Parse(rawResult interface{}) (*ParsedResult, error) {
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

		result.Findings = append(result.Findings, Finding{
			Severity:    strings.ToLower(riskStr),
			Title:       alertName,
			Description: description,
			Target:      url,
			RawData:     alertMap,
		})
	}

	result.Metadata["total_alerts"] = len(result.Findings)

	return result, nil
}

func (p *ZAPParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "owasp-zap",
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
	detail.Description = "Web application security issues detected by OWASP ZAP"
	
	sort.Strings(allFindings)
	detail.Findings = allFindings

	baseScore := models.GetSeverityScore(highestSeverity)
	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1
	}
	detail.Score = baseScore * findingCount

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
