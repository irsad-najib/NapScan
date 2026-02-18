package parser

import (
	"fmt"
	"strings"
)

type FFUFParser struct{}

func NewFFUFParser() *FFUFParser {
	return &FFUFParser{}
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

		// Create finding for anything interesting (e.g. 200, 403)
		// We filter 404s usually at scanner level, but if they are here, we might ignore them
		// unless instructed otherwise. assuming results are already filtered by scanner command details.

		severity := "info"
		if status == 200 {
			// Could be exposure
			if isSensitive(path) {
				severity = "medium"
			}
		}

		result.Findings = append(result.Findings, Finding{
			Source:      "ffuf",
			Title:       fmt.Sprintf("Path Discovered: %s", path),
			Description: fmt.Sprintf("Path %s returned status %d", path, status),
			Severity:    severity,
			Target:      url,
			Method:      "GET",
			Service:     "http",
			RawData:     resObj,
		})
	}

	result.Metadata["total_results"] = len(results)

	return result, nil
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

// Helper to check sensitivity (optional, kept for classification hint not scoring)
func isSensitive(path string) bool {
	sensitive := []string{".git", ".env", "config", "backup", "admin", "secret", "dump"}
	pathLower := strings.ToLower(path)
	for _, s := range sensitive {
		if strings.Contains(pathLower, s) {
			return true
		}
	}
	return false
}
