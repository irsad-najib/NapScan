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
	highestCVSS := 0.0
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

		description := fmt.Sprintf("%s (CVSS: %.1f)", name, sevVal)

		result.Findings = append(result.Findings, Finding{
			Severity:    "info", // placeholder
			Title:       name,
			Description: description,
			RawData:     map[string]interface{}{"cvss": sevVal, "threat": threat},
		})

		if sevVal > highestCVSS {
			highestCVSS = sevVal
		}
	}

	result.Metadata["highest_cvss"] = highestCVSS

	return result, nil
}

func (p *OpenVASParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "openvas",
		Findings: []string{},
	}

	highestCVSS := 0.0
	if v, ok := parsed.Metadata["highest_cvss"].(float64); ok {
		highestCVSS = v
	}

	var allFindings []string
	for _, finding := range parsed.Findings {
		allFindings = append(allFindings, finding.Description)
	}

	finalSeverity := models.SeverityInfo
	switch {
	case highestCVSS >= 9.0:
		finalSeverity = models.SeverityCritical
	case highestCVSS >= 7.0:
		finalSeverity = models.SeverityHigh
	case highestCVSS >= 4.0:
		finalSeverity = models.SeverityMedium
	case highestCVSS > 0:
		finalSeverity = models.SeverityLow
	}

	detail.NormalizedSeverity = finalSeverity
	detail.Description = "Vulnerabilities identified through OpenVAS scanning"

	sort.Strings(allFindings)
	detail.Findings = allFindings

	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1
	}

	detail.Score = highestCVSS*10 + findingCount*2
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
