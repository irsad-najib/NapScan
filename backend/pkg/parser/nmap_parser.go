package parser

import (
	"encoding/json"
	"fmt"
	"napscan-be/internal/models"
	"sort"
)

type NmapParser struct{}

func NewNmapParser() *NmapParser {
	return &NmapParser{}
}

// High-risk ports that should trigger HIGH severity
var highRiskPorts = map[int]bool{
	21:   true, // FTP
	23:   true, // Telnet
	445:  true, // SMB
	3389: true, // RDP
	1433: true, // MSSQL
	3306: true, // MySQL
}

func (p *NmapParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	// Convert rawResult to map
	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("nmap result is not a map")
	}

	// Extract hosts
	hosts, ok := resultMap["hosts"].([]interface{})
	if !ok {
		return result, nil // No hosts found
	}

	var allPorts []string
	var riskyPorts []string

	for _, h := range hosts {
		hostMap, ok := h.(map[string]interface{})
		if !ok {
			continue
		}

		ports, ok := hostMap["ports"].([]interface{})
		if !ok {
			continue
		}

		for _, p := range ports {
			portMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}

			// Get port ID
			var portID int
			if portNum, ok := portMap["portid"].(json.Number); ok {
				pid, _ := portNum.Int64()
				portID = int(pid)
			} else if portNum, ok := portMap["portid"].(float64); ok {
				portID = int(portNum)
			} else {
				continue
			}

			// Get service name
			serviceName := "unknown"
			if service, ok := portMap["service"].(map[string]interface{}); ok {
				if name, ok := service["name"].(string); ok {
					serviceName = name
				}
			}

			portStr := fmt.Sprintf("Port %d open (%s)", portID, serviceName)
			allPorts = append(allPorts, portStr)

			// Check if it's a high-risk port
			if highRiskPorts[portID] {
				riskyPorts = append(riskyPorts, portStr)
			}
		}
	}

	// Create findings based on ports discovered
	if len(riskyPorts) > 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "high",
			Title:       "High-Risk Ports Open",
			Description: fmt.Sprintf("Found %d high-risk ports open", len(riskyPorts)),
			RawData:     riskyPorts,
		})
	} else if len(allPorts) >= 5 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "medium",
			Title:       "Multiple Ports Open",
			Description: fmt.Sprintf("Found %d open ports", len(allPorts)),
			RawData:     allPorts,
		})
	} else if len(allPorts) > 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "low",
			Title:       "Open Ports Detected",
			Description: fmt.Sprintf("Found %d open ports", len(allPorts)),
			RawData:     allPorts,
		})
	} else {
		result.Findings = append(result.Findings, Finding{
			Severity:    "info",
			Title:       "No Open Ports",
			Description: "No open ports detected",
			RawData:     []string{},
		})
	}

	result.Metadata["total_ports"] = len(allPorts)
	result.Metadata["risky_ports"] = len(riskyPorts)

	return result, nil
}

func (p *NmapParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "nmap",
		Findings: []string{},
	}

	// Determine the highest severity from findings
	highestSeverity := models.SeverityInfo
	var allFindings []string

	for _, finding := range parsed.Findings {
		normalized := models.NormalizeSeverity(finding.Severity)
		if models.GetSeverityScore(normalized) > models.GetSeverityScore(highestSeverity) {
			highestSeverity = normalized
		}

		// Extract findings from RawData
		if ports, ok := finding.RawData.([]string); ok {
			allFindings = append(allFindings, ports...)
		}
	}

	detail.NormalizedSeverity = highestSeverity
	detail.Description = "Open ports detected that may expose services to unauthorized access"
	
	// Sort findings for determinism
	sort.Strings(allFindings)
	detail.Findings = allFindings

	// Calculate score (will be multiplied by scanner weight in risk engine)
	baseScore := models.GetSeverityScore(highestSeverity)
	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1 // Avoid zero multiplication
	}
	detail.Score = baseScore * findingCount

	return detail, nil
}

func (p *NmapParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
	// Aggregate all nmap results for this batch
	aggregatedFindings := []string{}
	highestSeverity := models.SeverityInfo

	for _, scanResult := range rawResults {
		parsed, err := p.Parse(scanResult.Result)
		if err != nil {
			continue // Skip invalid results
		}

		normalized, err := p.Normalize(parsed)
		if err != nil {
			continue
		}

		// Track highest severity
		if models.GetSeverityScore(normalized.NormalizedSeverity) > models.GetSeverityScore(highestSeverity) {
			highestSeverity = normalized.NormalizedSeverity
		}

		// Aggregate findings
		aggregatedFindings = append(aggregatedFindings, normalized.Findings...)
	}

	// Remove duplicates and sort
	uniqueFindings := removeDuplicates(aggregatedFindings)
	sort.Strings(uniqueFindings)

	detail := &models.ScannerRiskDetail{
		Scanner:            "nmap",
		NormalizedSeverity: highestSeverity,
		Description:        "Open ports detected that may expose services to unauthorized access",
		Findings:           uniqueFindings,
	}

	// Calculate score
	baseScore := models.GetSeverityScore(highestSeverity)
	findingCount := float64(len(uniqueFindings))
	if findingCount == 0 {
		findingCount = 1
	}
	detail.Score = baseScore * findingCount

	return detail, nil
}

// Helper function to remove duplicate strings
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
