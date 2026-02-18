package parser

import (
	"encoding/json"
	"fmt"
)

type NmapParser struct{}

func NewNmapParser() *NmapParser {
	return &NmapParser{}
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
			productName := ""
			version := ""

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
				if prod, ok := service["product"].(string); ok {
					productName = prod
				}
				if ver, ok := service["version"].(string); ok {
					version = ver
				}
			}

			portStr := fmt.Sprintf("Port %d open (%s)", portID, serviceName)
			allPorts = append(allPorts, portStr)

			// Create a finding for EACH open port (Exposure)
			// The Intelligence Service will decide if it's risky
			finding := Finding{
				Source:      "nmap",
				Title:       fmt.Sprintf("Open Port %d/%s", portID, serviceName),
				Description: fmt.Sprintf("Port %d is open running %s %s %s", portID, serviceName, productName, version),
				Service:     serviceName,
				Product:     productName,
				Version:     version,
				Method:      "TCP", // defaulting to TCP for now, need valid extraction if mixed
				Target:      fmt.Sprintf("%d", portID),
				Severity:    "INFO", // Default, will be recalculated by Intelligence
				RawData:     portMap,
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	result.Metadata["total_ports"] = len(allPorts)

	return result, nil
}
