package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"sort"
	"strconv"
)

type OpenVASParser struct{}

func NewOpenVASParser() *OpenVASParser {
	return &OpenVASParser{}
}

func (p *OpenVASParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("openvas result is not a map")
	}

	resultsContainer, ok := resultMap["results"].(map[string]interface{})
	if !ok {
		return result, nil
	}

	findings, ok := resultsContainer["result"].([]interface{})
	if !ok {
		return result, nil
	}

	for _, finding := range findings {
		fMap, ok := finding.(map[string]interface{})
		if !ok {
			continue
		}

		sevStr, _ := fMap["severity"].(string)
		name, _ := fMap["name"].(string)
		threat, _ := fMap["threat"].(string)

		sevVal, err := strconv.ParseFloat(sevStr, 64)
		if err != nil {
			continue
		}

		// Map CVSS score to severity level
		var severity string
		if sevVal >= 9.0 {
			severity = "critical"
		} else if sevVal >= 7.0 {
			severity = "high"
		} else if sevVal >= 4.0 {
			severity = "medium"
		} else if sevVal > 0.0 {
			severity = "low"
		} else {
			severity = "info"
		}

		description := fmt.Sprintf("%s (CVSS: %.1f)", name, sevVal)

		result.Findings = append(result.Findings, Finding{
			Severity:    severity,
			Title:       name,
			Description: description,
			RawData:     map[string]interface{}{"cvss": sevVal, "threat": threat},
		})
	}

	result.Metadata["total_findings"] = len(result.Findings)

	return result, nil
}

func (p *OpenVASParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "openvas",
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
	detail.Description = "Vulnerabilities identified through OpenVAS scanning"
	
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

func (p *OpenVASParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
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
		Scanner:            "openvas",
		NormalizedSeverity: highestSeverity,
		Description:        "Vulnerabilities identified through OpenVAS scanning",
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
