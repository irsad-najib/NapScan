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
var sensitivePathRisk = map[string]int{

	// ===== Source Control / Secrets =====
	"/.git":        95,
	"/.git/config": 95,
	"/.svn":        90,
	"/.hg":         90,
	"/.env":        95,
	"/.env.local":  95,
	"/secrets":     95,
	"/secret":      95,
	"/credentials": 95,
	"/id_rsa":      95,
	"/.ssh":        95,

	// ===== Config Files =====
	"/config":        70,
	"/config.php":    85,
	"/settings.php":  85,
	"/web.config":   85,
	"/application.yml": 80,
	"/application.properties": 80,

	// ===== Backup / Dump =====
	"/backup":     85,
	"/backups":    85,
	"/backup.zip": 90,
	"/backup.sql": 95,
	"/dump.sql":   95,
	"/db.sql":     95,
	"/database.sql": 95,
	"/site.bak":   90,

	// ===== Admin Panels =====
	"/admin":          80,
	"/administrator":  80,
	"/adminpanel":     80,
	"/manage":         75,
	"/management":     75,
	"/cpanel":         80,
	"/dashboard":      70,

	// ===== CMS Specific =====
	"/wp-admin":     80,
	"/wp-login":     80,
	"/wp-config":    95,
	"/joomla":       70,
	"/administrator/index.php": 80,

	// ===== Database Tools =====
	"/phpmyadmin": 95,
	"/pma":        95,
	"/adminer":    90,

	// ===== Debug / Info Leak =====
	"/phpinfo":     90,
	"/info.php":    90,
	"/debug":       80,
	"/debugbar":    80,
	"/error.log":   85,
	"/logs":        75,

	// ===== Cloud / DevOps =====
	"/.aws":            95,
	"/.docker":         80,
	"/docker-compose.yml": 90,
	"/kubeconfig":      95,
	"/.kube":           95,

	// ===== API / Keys =====
	"/api/keys": 95,
	"/apikey":   95,
	"/token":    90,
	"/tokens":   90,
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

	totalPathRisk := 0
	highestPathRisk := 0

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
			if risk := getSensitivePathRisk(path); risk > 0 {
				status200Sensitive = append(
					status200Sensitive,
					fmt.Sprintf("%s (200)", path),
				)
				totalPathRisk += risk
				if risk > highestPathRisk {
					highestPathRisk = risk
				}
			} else {
				status200 = append(status200, fmt.Sprintf("%s (200)", path))
}
		case 403, 401:
			status403 = append(status403, fmt.Sprintf("%s (%d)", path, status))
		}
	}

	// Create findings based on discovered paths
	severity := "info"

	if highestPathRisk >= 90 {
		severity = "high"
	} else if highestPathRisk >= 70 {
		severity = "medium"
	} else if len(status200) > 0 {
		severity = "low"
}

	result.Findings = append(result.Findings, Finding{
		Severity:    severity,
		Title:       "Web Path Enumeration Result",
		Description: fmt.Sprintf("Found %d paths (%d sensitive)", len(status200)+len(status200Sensitive), len(status200Sensitive)),
		RawData:     append(status200Sensitive, status200...),
	})

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
	detail.Score = baseScore*10 + findingCount*2

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
func getSensitivePathRisk(path string) int {
	pathLower := strings.ToLower(path)
	for pattern, risk := range sensitivePathRisk {
		if strings.Contains(pathLower, pattern) {
			return risk
		}
	}
	return 0
}