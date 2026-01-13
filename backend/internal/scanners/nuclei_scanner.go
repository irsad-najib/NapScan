package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"napscan-be/internal/scanner"
)

// NucleiScanner implements the Scanner interface for Nuclei
type NucleiScanner struct{}

// NewNucleiScanner creates a new Nuclei scanner
func NewNucleiScanner() *NucleiScanner {
	return &NucleiScanner{}
}

// Name returns the scanner identifier
func (s *NucleiScanner) Name() string {
	return "nuclei"
}

// Execute runs a Nuclei scan
func (s *NucleiScanner) Execute(ctx context.Context, config scanner.ScanConfig) (interface{}, error) {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei_%s.jsonl", time.Now().Format("20060102150405")))
	defer os.Remove(tmpFile)
	
	args := []string{
		"-target", config.Target,
		"-jsonl",
		"-o", tmpFile,
		"-silent",
		"-nc",
	}
	
	// Add severity filter if specified
	if severity, ok := config.Options["severity"].(string); ok && severity != "" {
		args = append(args, "-severity", severity)
	}
	
	// Add template filter if specified
	if templates, ok := config.Options["templates"].(string); ok && templates != "" {
		args = append(args, "-t", templates)
	}
	
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %w, output: %s", err, string(output))
	}
	
	// Read results from JSONL file
	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read nuclei output: %w", err)
	}
	
	trimmed := strings.TrimSpace(string(jsonData))
	if trimmed == "" {
		return []map[string]interface{}{}, nil
	}
	
	// Parse JSONL (one JSON object per line)
	lines := strings.Split(trimmed, "\n")
	results := make([]map[string]interface{}, 0, len(lines))
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			return nil, fmt.Errorf("failed to parse nuclei jsonl: %w", err)
		}
		
		results = append(results, obj)
	}
	
	return results, nil
}

// Normalize converts Nuclei results to unified vulnerability format
func (s *NucleiScanner) Normalize(rawResult interface{}) ([]scanner.Vulnerability, error) {
	results, ok := rawResult.([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid result type for nuclei scanner")
	}
	
	var vulnerabilities []scanner.Vulnerability
	
	for _, result := range results {
		// Extract fields from Nuclei result
		templateID := getStringField(result, "template-id")
		templateName := getStringField(result, "info", "name")
		severityStr := getStringField(result, "info", "severity")
		description := getStringField(result, "info", "description")
		matched := getStringField(result, "matched-at")
		extractedResults := getStringField(result, "extracted-results")
		
		// Map Nuclei severity to our severity
		severity := mapNucleiSeverity(severityStr)
		
		// Build vulnerability
		vuln := scanner.Vulnerability{
			ID:            fmt.Sprintf("nuclei-%s-%s", templateID, matched),
			Title:         templateName,
			Severity:      severity,
			Description:   description,
			AffectedAsset: []string{matched},
			SourceTool:    "nuclei",
			Evidence:      extractedResults,
			Remediation:   fmt.Sprintf("Review and remediate the vulnerability identified by template: %s", templateID),
			Metadata: map[string]interface{}{
				"template_id": templateID,
				"raw_result":  result,
			},
		}
		
		// Extract CVE if present
		if tags, ok := result["info"].(map[string]interface{})["tags"]; ok {
			if tagsStr, ok := tags.(string); ok && strings.Contains(tagsStr, "cve") {
				// Try to extract CVE ID from tags or metadata
				if cveID := extractCVE(tagsStr); cveID != "" {
					vuln.CVE = cveID
				}
			}
		}
		
		// Extract CWE if present
		if classification, ok := result["info"].(map[string]interface{})["classification"]; ok {
			if classMap, ok := classification.(map[string]interface{}); ok {
				if cweID, ok := classMap["cwe-id"].(string); ok {
					vuln.CWE = cweID
				}
				if cvssScore, ok := classMap["cvss-score"].(float64); ok {
					vuln.CVSS = cvssScore
				}
			}
		}
		
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	return vulnerabilities, nil
}

// Validate checks if nuclei is available
func (s *NucleiScanner) Validate() error {
	cmd := exec.Command("nuclei", "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nuclei not found or not executable: %w", err)
	}
	
	if !strings.Contains(string(output), "Nuclei") {
		return fmt.Errorf("nuclei validation failed: unexpected output")
	}
	
	return nil
}

// Helper functions

func getStringField(data map[string]interface{}, keys ...string) string {
	current := data
	
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - get the string value
			if val, ok := current[key].(string); ok {
				return val
			}
			return ""
		}
		
		// Intermediate key - traverse deeper
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return ""
		}
	}
	
	return ""
}

func mapNucleiSeverity(nucleiSeverity string) scanner.Severity {
	switch strings.ToLower(nucleiSeverity) {
	case "critical":
		return scanner.SeverityCritical
	case "high":
		return scanner.SeverityHigh
	case "medium":
		return scanner.SeverityMedium
	case "low":
		return scanner.SeverityLow
	case "info", "informational":
		return scanner.SeverityInfo
	default:
		return scanner.SeverityInfo
	}
}

func extractCVE(text string) string {
	// Simple CVE extraction - in production, use proper regex
	parts := strings.Fields(text)
	for _, part := range parts {
		if strings.HasPrefix(strings.ToUpper(part), "CVE-") {
			return strings.ToUpper(part)
		}
	}
	return ""
}
