package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"sort"
)

type NucleiParser struct{}

func NewNucleiParser() *NucleiParser {
	return &NucleiParser{}
}

func (p *NucleiParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	// Nuclei returns an array of findings
	resList, ok := rawResult.([]interface{})
	if !ok {
		return nil, fmt.Errorf("nuclei result is not an array")
	}

	for _, item := range resList {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		info, ok := itemMap["info"].(map[string]interface{})
		if !ok {
			continue
		}

		severity, _ := info["severity"].(string)
		name, _ := info["name"].(string)
		matchedAt, _ := itemMap["matched-at"].(string)

		finding := Finding{
			Severity:    severity,
			Title:       name,
			Description: fmt.Sprintf("%s on %s", name, matchedAt),
			Target:      matchedAt,
			RawData:     itemMap,
		}

		result.Findings = append(result.Findings, finding)
	}

	result.Metadata["total_findings"] = len(result.Findings)

	return result, nil
}

func (p *NucleiParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "nuclei",
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
	detail.Description = "Security issues identified through Nuclei template scanning"
	
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

func (p *NucleiParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
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
		Scanner:            "nuclei",
		NormalizedSeverity: highestSeverity,
		Description:        "Security issues identified through Nuclei template scanning",
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
