package scanners

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"

	"napscan-be/internal/models"
	"napscan-be/internal/scanner"
)

// NmapScanner implements the Scanner interface for Nmap
type NmapScanner struct{}

// NewNmapScanner creates a new Nmap scanner
func NewNmapScanner() *NmapScanner {
	return &NmapScanner{}
}

// Name returns the scanner identifier
func (s *NmapScanner) Name() string {
	return "nmap"
}

// Execute runs an Nmap scan
func (s *NmapScanner) Execute(ctx context.Context, config scanner.ScanConfig) (interface{}, error) {
	// Build nmap command arguments
	args := []string{"-sV", "-n", "-T4", "-oX", "-"}
	
	// Add custom options if provided
	if scanType, ok := config.Options["scan_type"].(string); ok && scanType != "" {
		args[0] = scanType
	}
	
	if ports, ok := config.Options["ports"].(string); ok && ports != "" {
		args = append(args, "-p", ports)
	}
	
	args = append(args, config.Target)
	
	// Execute nmap command
	cmd := exec.CommandContext(ctx, "nmap", args...)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap execution failed: %w, output: %s", err, string(output))
	}
	
	// Parse XML output
	var result models.NmapRun
	if err := xml.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse nmap output: %w", err)
	}
	
	return result, nil
}

// Normalize converts Nmap results to unified vulnerability format
func (s *NmapScanner) Normalize(rawResult interface{}) ([]scanner.Vulnerability, error) {
	nmapRun, ok := rawResult.(models.NmapRun)
	if !ok {
		return nil, fmt.Errorf("invalid result type for nmap scanner")
	}
	
	var vulnerabilities []scanner.Vulnerability
	
	// Map of high-risk ports
	highRiskPorts := map[string]string{
		"21":    "FTP - Unencrypted file transfer",
		"23":    "Telnet - Unencrypted remote access",
		"445":   "SMB - File sharing",
		"3389":  "RDP - Remote Desktop",
		"3306":  "MySQL - Database exposed",
		"5432":  "PostgreSQL - Database exposed",
		"27017": "MongoDB - Database exposed",
		"6379":  "Redis - Database exposed",
	}
	
	// Process each host
	for _, host := range nmapRun.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		
		ipAddr := host.Addresses[0].Addr
		
		// Check for open ports
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			
			portID := port.PortID
			asset := fmt.Sprintf("%s:%s", ipAddr, portID)
			
			// Check if it's a high-risk port
			if riskReason, isHighRisk := highRiskPorts[portID]; isHighRisk {
				severity := scanner.SeverityMedium
				if portID == "23" || portID == "21" {
					severity = scanner.SeverityHigh
				}
				
				vuln := scanner.Vulnerability{
					ID:            fmt.Sprintf("nmap-%s-%s", ipAddr, portID),
					Title:         fmt.Sprintf("High-risk service exposed: %s", port.Service.Name),
					Severity:      severity,
					Description:   fmt.Sprintf("%s is exposed on %s", riskReason, asset),
					AffectedAsset: []string{asset},
					SourceTool:    "nmap",
					Evidence:      fmt.Sprintf("Port %s/%s is open, service: %s %s", portID, port.Protocol, port.Service.Name, port.Service.Version),
					Remediation:   fmt.Sprintf("Review the necessity of %s service exposure. Consider firewall rules or VPN access.", port.Service.Name),
					Metadata: map[string]interface{}{
						"port":     portID,
						"protocol": port.Protocol,
						"service":  port.Service.Name,
						"version":  port.Service.Version,
						"product":  port.Service.Product,
					},
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
			}
			
			// Check for outdated or vulnerable service versions
			if port.Service.Product != "" && port.Service.Version != "" {
				// This is a simplified check - in production, you'd check against a vulnerability database
				vuln := scanner.Vulnerability{
					ID:            fmt.Sprintf("nmap-svc-%s-%s-%s", ipAddr, portID, port.Service.Name),
					Title:         fmt.Sprintf("Service version detection: %s", port.Service.Product),
					Severity:      scanner.SeverityInfo,
					Description:   fmt.Sprintf("Detected %s version %s on port %s", port.Service.Product, port.Service.Version, portID),
					AffectedAsset: []string{asset},
					SourceTool:    "nmap",
					Evidence:      fmt.Sprintf("%s %s running on %s", port.Service.Product, port.Service.Version, asset),
					Remediation:   "Verify this is the latest version and check for known vulnerabilities",
					Metadata: map[string]interface{}{
						"port":     portID,
						"protocol": port.Protocol,
						"service":  port.Service.Name,
						"version":  port.Service.Version,
						"product":  port.Service.Product,
					},
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	
	return vulnerabilities, nil
}

// Validate checks if nmap is available
func (s *NmapScanner) Validate() error {
	cmd := exec.Command("nmap", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nmap not found or not executable: %w", err)
	}
	
	if !strings.Contains(string(output), "Nmap") {
		return fmt.Errorf("nmap validation failed: unexpected output")
	}
	
	return nil
}
