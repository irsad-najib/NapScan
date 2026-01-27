package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"sort"
	"strings"
)

type NucleiParser struct{}

func NewNucleiParser() *NucleiParser {
	return &NucleiParser{}
}

// Map Nuclei severity to standard severity levels
var nucleiSeverityRisk = map[string]int{
	"info":     10,
	"low":      30,
	"medium":   60,
	"high":     80,
	"critical": 95,
}

var nucleiCategoryBonus = map[string]int{
	"exposed-panels": 10,
	"misconfiguration": 10,
	"default-login": 15,
	"rce": 20,
	"lfi": 20,
	"sqli": 20,
	"xss": 10,
	"takeover": 25,
}

func (p *NucleiParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	// Nuclei returns an array of findings, but sometimes might be a single map (e.g. single JSONL line)
	var resList []interface{}

	if asMap, ok := rawResult.(map[string]interface{}); ok {
		resList = []interface{}{asMap}
	} else if asList, ok := rawResult.([]interface{}); ok {
		resList = asList
	} else {
		return nil, fmt.Errorf("nuclei result is not an array or map")
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

		category, _ := info["category"].(string)

		severity, _ := info["severity"].(string)
		name, _ := info["name"].(string)
		matchedAt, _ := itemMap["matched-at"].(string)

		finding := Finding{
			Severity:    severity,
			Title:       name,
			Description: fmt.Sprintf("%s [%s] on %s", name, category, matchedAt),
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

	highestRisk := 0
	var allFindings []string

	for _, finding := range parsed.Findings {

		sev := strings.ToLower(finding.Severity)
		baseRisk := nucleiSeverityRisk[sev]

		// extract category from description
		category := ""
		if strings.Contains(finding.Description, "[") {
			parts := strings.Split(finding.Description, "[")
			if len(parts) > 1 {
				category = strings.Split(parts[1], "]")[0]
			}
		}

		if bonus, ok := nucleiCategoryBonus[category]; ok {
			baseRisk += bonus
		}

		if baseRisk > highestRisk {
			highestRisk = baseRisk
		}

		allFindings = append(allFindings, finding.Description)
	}

	// Map numeric risk → severity
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
	detail.Description = "Security issues identified through Nuclei template scanning"

	sort.Strings(allFindings)
	detail.Findings = allFindings

	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1
	}

	detail.Score = float64(highestRisk)*10 + findingCount*2
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
