package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"sort"
	"strings"
)

type FFUFParser struct{}

func NewFFUFParser() *FFUFParser {
	return &FFUFParser{}
}

// Sensitive paths that should trigger HIGH severity when found with 200 status
var sensitivePaths = map[string]bool{
	"/admin":     true,
	"/backup":    true,
	"/.git":      true,
	"/.env":      true,
	"/.svn":      true,
	"/config":    true,
	"/database":  true,
	"/.aws":      true,
	"/api/keys":  true,
	"/phpinfo":   true,
	"/phpmyadmin": true,
}

func (p *FFUFParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("ffuf result is not a map")
	}

	results, ok := resultMap["results"].([]interface{})
	if !ok {
		return result, nil // No results found
	}

	var status200 []string
	var status200Sensitive []string
	var status403 []string

	for _, r := range results {
		resObj, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		// Get status code
		var status int
		if statusFloat, ok := resObj["status"].(float64); ok {
			status = int(statusFloat)
		} else {
			continue
		}

		// Get URL
		url, _ := resObj["url"].(string)
		
		// Extract path from URL
		path := extractPath(url)

		switch status {
		case 200:
			if isSensitivePath(path) {
				status200Sensitive = append(status200Sensitive, fmt.Sprintf("%s (200)", path))
			} else {
				status200 = append(status200, fmt.Sprintf("%s (200)", path))
			}
		case 403, 401:
			status403 = append(status403, fmt.Sprintf("%s (%d)", path, status))
		}
	}

	// Create findings based on discovered paths
	if len(status200Sensitive) > 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "high",
			Title:       "Sensitive Paths Accessible",
			Description: fmt.Sprintf("Found %d sensitive paths with 200 status", len(status200Sensitive)),
			RawData:     status200Sensitive,
		})
	}

	if len(status200) > 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "medium",
			Title:       "Accessible Paths Discovered",
			Description: fmt.Sprintf("Found %d accessible paths", len(status200)),
			RawData:     status200,
		})
	}

	if len(status403) > 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "low",
			Title:       "Protected Paths Discovered",
			Description: fmt.Sprintf("Found %d protected paths (403/401)", len(status403)),
			RawData:     status403,
		})
	}

	if len(status200Sensitive) == 0 && len(status200) == 0 && len(status403) == 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "info",
			Title:       "No Paths Discovered",
			Description: "No accessible paths found",
			RawData:     []string{},
		})
	}

	result.Metadata["total_results"] = len(results)
	result.Metadata["sensitive_count"] = len(status200Sensitive)

	return result, nil
}

func (p *FFUFParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "ffuf",
		Findings: []string{},
	}

	highestSeverity := models.SeverityInfo
	var allFindings []string

	for _, finding := range parsed.Findings {
		normalized := models.NormalizeSeverity(finding.Severity)
		if models.GetSeverityScore(normalized) > models.GetSeverityScore(highestSeverity) {
			highestSeverity = normalized
		}

		if paths, ok := finding.RawData.([]string); ok {
			allFindings = append(allFindings, paths...)
		}
	}

	detail.NormalizedSeverity = highestSeverity
	detail.Description = "Sensitive directories discovered through fuzzing"
	
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

func (p *FFUFParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
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
		Scanner:            "ffuf",
		NormalizedSeverity: highestSeverity,
		Description:        "Sensitive directories discovered through fuzzing",
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

// Helper function to extract path from URL
func extractPath(url string) string {
	// Remove protocol
	if idx := strings.Index(url, "://"); idx != -1 {
		url = url[idx+3:]
	}
	
	// Remove domain
	if idx := strings.Index(url, "/"); idx != -1 {
		return url[idx:]
	}
	
	return "/"
}

// Helper function to check if path is sensitive
func isSensitivePath(path string) bool {
	pathLower := strings.ToLower(path)
	for sensitive := range sensitivePaths {
		if strings.Contains(pathLower, sensitive) {
			return true
		}
	}
	return false
}
