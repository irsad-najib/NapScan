package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"sort"
	"strings"
)

type NiktoParser struct{}

func NewNiktoParser() *NiktoParser {
	return &NiktoParser{}
}

func (p *NiktoParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("nikto result is not a map")
	}

	// Nikto structure can vary, try to extract vulnerabilities
	vulnerabilities, ok := resultMap["vulnerabilities"].([]interface{})
	if !ok {
		// Try alternative structure
		if items, ok := resultMap["items"].([]interface{}); ok {
			vulnerabilities = items
		} else {
			return result, nil
		}
	}

	for _, vuln := range vulnerabilities {
		vulnMap, ok := vuln.(map[string]interface{})
		if !ok {
			continue
		}

		description, _ := vulnMap["description"].(string)
		severity := classifyNiktoSeverity(description)

		result.Findings = append(result.Findings, Finding{
			Severity:    severity,
			Title:       extractTitle(description),
			Description: description,
			RawData:     vulnMap,
		})
	}

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "info",
			Title:       "No Issues Found",
			Description: "No web server vulnerabilities detected",
			RawData:     nil,
		})
	}

	result.Metadata["total_findings"] = len(result.Findings)

	return result, nil
}

func (p *NiktoParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "nikto",
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
	detail.Description = "Web server vulnerabilities detected by Nikto scanner"
	
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

func (p *NiktoParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
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
		Scanner:            "nikto",
		NormalizedSeverity: highestSeverity,
		Description:        "Web server vulnerabilities detected by Nikto scanner",
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

// Helper function to classify Nikto findings by severity
func classifyNiktoSeverity(description string) string {
	descLower := strings.ToLower(description)

	// Critical indicators
	if strings.Contains(descLower, "sql injection") || strings.Contains(descLower, "remote code execution") {
		return "critical"
	}

	// High indicators
	if strings.Contains(descLower, "xss") || strings.Contains(descLower, "directory traversal") ||
		strings.Contains(descLower, "file inclusion") {
		return "high"
	}

	// Medium indicators
	if strings.Contains(descLower, "outdated") || strings.Contains(descLower, "information disclosure") ||
		strings.Contains(descLower, "misconfiguration") {
		return "medium"
	}

	// Low indicators
	if strings.Contains(descLower, "missing header") || strings.Contains(descLower, "banner") {
		return "low"
	}

	return "info"
}

// Helper function to extract title from description
func extractTitle(description string) string {
	if len(description) > 80 {
		return description[:77] + "..."
	}
	return description
}
