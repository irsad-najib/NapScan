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
var portRiskScore = map[int]int{
	// Remote Access
	21:   80,
	22:   70,
	23:   90,
	3389: 95,
	5900: 85,

	// Web
	80:   40,
	443:  30,
	8080: 60,
	8000: 60,
	8888: 65,
	3000: 50,
	5000: 50,
	5173: 50,
	4200: 50,

	// Database
	1433:  90,
	3306:  85,
	5432:  80,
	27017: 90,
	6379:  90,
	9200:  85,
	1521:  85,

	// File Sharing
	445:  95,
	139:  80,
	2049: 85,
	69:   70,

	// Mail
	25:  60,
	110: 60,
	143: 60,
	465: 60,
	587: 60,
	993: 60,
	995: 60,

	// Infra
	2375:  95,
	6443:  95,
	10250: 90,
	5601:  80,
	9090:  70,

	// Network
	53:  50,
	123: 50,
	161: 70,
	389: 70,
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

	// Collect hosts from multiple possible locations
	var hosts []interface{}

	// 1. Direct "hosts" array (flat structure)
	if h, ok := resultMap["hosts"].([]interface{}); ok {
		hosts = append(hosts, h...)
	}

	// 2. "tcp" -> "hosts" structure
	if tcp, ok := resultMap["tcp"].(map[string]interface{}); ok {
		if h, ok := tcp["hosts"].([]interface{}); ok {
			hosts = append(hosts, h...)
		}
	}

	// 3. "udp" -> "hosts" structure
	if udp, ok := resultMap["udp"].(map[string]interface{}); ok {
		if h, ok := udp["hosts"].([]interface{}); ok {
			hosts = append(hosts, h...)
		}
	}

	if len(hosts) == 0 {
		return result, nil // No hosts found
	}

	var allPorts []string
	var riskyPorts []string
	var totalPortRisk int
	var highestPortRisk int

	for _, h := range hosts {
		hostMap, ok := h.(map[string]interface{})
		if !ok {
			continue
		}


		// Nmap JSON structure can be tricky due to XML-to-JSON conversion or Struct layout
		// Check if "ports" is a map (Struct wrapper) or array
		var ports []interface{}
		

		if portsMap, ok := hostMap["ports"].(map[string]interface{}); ok {
			// Found struct wrapper, look for inner "ports" array
			if p, ok := portsMap["ports"].([]interface{}); ok {
				ports = p
			}
		} else if p, ok := hostMap["ports"].([]interface{}); ok {
			// Direct array (unlikely with current model, but good fallback)
			ports = p
		}

		if ports == nil {
			continue
		}

		for _, p := range ports {
			portMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}

			// Get port ID
			var portID int
			if portNum, ok := portMap["port"].(json.Number); ok {
				pid, _ := portNum.Int64()
				portID = int(pid)
			} else if portNum, ok := portMap["port"].(float64); ok {
				portID = int(portNum)
			} else if portStr, ok := portMap["port"].(string); ok {
				var pid int
				if _, err := fmt.Sscanf(portStr, "%d", &pid); err == nil {
					portID = pid
				} else {
					continue
				}
			} else {
				continue
			}

			// Get service name
			serviceName := "unknown"
			var service map[string]interface{}
			
			if s, ok := portMap["service"].(map[string]interface{}); ok {
				service = s
			} else if s, ok := portMap["Service"].(map[string]interface{}); ok {
				service = s
			}

			if service != nil {
				if name, ok := service["name"].(string); ok {
					serviceName = name
				}
			}

			portStr := fmt.Sprintf("Port %d open (%s)", portID, serviceName)
			allPorts = append(allPorts, portStr)

			// Check if it's a high-risk port
			if risk, ok := portRiskScore[portID]; ok {
				riskyPorts = append(riskyPorts, portStr)
				totalPortRisk += risk

				if risk > highestPortRisk {
					highestPortRisk = risk
				}
			}
		}
	}

	// Create findings based on ports discovered
	severity := "info"

	if highestPortRisk >= 90 {
		severity = "high"
	} else if highestPortRisk >= 70 {
		severity = "medium"
	} else if len(allPorts) > 0 {
		severity = "low"
	}
	result.Findings = append(result.Findings, Finding{
		Severity:    severity,
		Title:       "Open Ports Detected",
		Description: fmt.Sprintf("Found %d open ports (%d risky)", len(allPorts), len(riskyPorts)),
		RawData:     allPorts,
	})

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
	detail.Score = baseScore*10 + findingCount*2

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
