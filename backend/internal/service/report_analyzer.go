package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"napscan-be/internal/models"
)

// ReportAnalyzer analyzes scan results and generates security reports
type ReportAnalyzer struct{}

func NewReportAnalyzer() *ReportAnalyzer {
	return &ReportAnalyzer{}
}

// AnalyzeResults processes all scan results and generates a comprehensive report
func (ra *ReportAnalyzer) AnalyzeResults(results map[string]interface{}) *models.ScanReport {
	report := &models.ScanReport{
		Timestamp:       time.Now(),
		Vulnerabilities: []models.Vulnerability{},
		Recommendations: []models.Recommendation{},
	}

	// Analyze Nmap results
	nmapData := ra.extractNmapData(results)
	if nmapData != nil {
		ra.analyzeNmapData(nmapData, report)
	}

	// Calculate overall risk score
	report.RiskScore = ra.calculateRiskScore(report)

	return report
}

// extractNmapData extracts nmap data from results map
func (ra *ReportAnalyzer) extractNmapData(results map[string]interface{}) *CombinedScanResponse {
	// Try to find nmap data in different possible keys
	possibleKeys := []string{"nmap", "api_a", "api_b", "api_c", "api_d", "api_e"}
	
	for _, key := range possibleKeys {
		if data, ok := results[key]; ok {
			// Try to convert to CombinedScanResponse
			jsonBytes, err := json.Marshal(data)
			if err != nil {
				continue
			}
			
			var nmapData CombinedScanResponse
			if err := json.Unmarshal(jsonBytes, &nmapData); err == nil {
				return &nmapData
			}
		}
	}
	
	return nil
}

// analyzeNmapData analyzes nmap scan results
func (ra *ReportAnalyzer) analyzeNmapData(nmapData *CombinedScanResponse, report *models.ScanReport) {
	var allHosts []models.HostAnalysis
	var allPorts []models.PortAnalysis
	serviceMap := make(map[string]*models.ServiceInfo)
	
	summary := models.ScanSummary{}
	
	// Process TCP results
	if nmapData.TCP != nil {
		ra.processNmapRun(nmapData.TCP, &allHosts, &allPorts, serviceMap, &summary, "TCP")
	}
	
	// Process UDP results
	if nmapData.UDP != nil {
		ra.processNmapRun(nmapData.UDP, &allHosts, &allPorts, serviceMap, &summary, "UDP")
	}
	
	// Convert service map to slice
	var services []models.ServiceInfo
	for _, svc := range serviceMap {
		services = append(services, *svc)
	}
	
	summary.TotalHosts = len(allHosts)
	summary.TotalOpenPorts = summary.HighRiskPorts + summary.MediumRiskPorts + summary.LowRiskPorts
	summary.TotalServices = len(services)
	
	report.Summary = summary
	report.NetworkAnalysis = models.NetworkAnalysis{
		Hosts:     allHosts,
		OpenPorts: allPorts,
		Services:  services,
	}
	
	// Generate vulnerabilities based on findings
	ra.generateVulnerabilities(allPorts, report)
	
	// Generate recommendations
	ra.generateRecommendations(allPorts, report)
}

// processNmapRun processes a single nmap run (TCP or UDP)
func (ra *ReportAnalyzer) processNmapRun(
	run *models.NmapRun,
	hosts *[]models.HostAnalysis,
	ports *[]models.PortAnalysis,
	serviceMap map[string]*models.ServiceInfo,
	summary *models.ScanSummary,
	scanType string,
) {
	for _, host := range run.Hosts {
		var ipAddress string
		if len(host.Addresses) > 0 {
			ipAddress = host.Addresses[0].Addr
		}
		
		openPortCount := 0
		hostRiskLevel := "Low"
		
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			
			openPortCount++
			
			// Analyze port risk
			portAnalysis := models.PortAnalysis{
				Port:     port.PortID,
				Protocol: port.Proto,
				State:    port.State.State,
				Service:  port.Service.Name,
			}
			
			risk := ra.assessPortRisk(port.PortID, port.Service.Name)
			portAnalysis.RiskLevel = risk.Level
			portAnalysis.RiskReason = risk.Reason
			
			*ports = append(*ports, portAnalysis)
			
			// Update summary counts
			switch risk.Level {
			case "High":
				summary.HighRiskPorts++
				hostRiskLevel = "High"
			case "Medium":
				summary.MediumRiskPorts++
				if hostRiskLevel != "High" {
					hostRiskLevel = "Medium"
				}
			default:
				summary.LowRiskPorts++
			}
			
			// Track services
			serviceName := port.Service.Name
			if serviceName == "" {
				serviceName = "unknown"
			}
			
			serviceKey := fmt.Sprintf("%s:%s", serviceName, port.PortID)
			if svc, exists := serviceMap[serviceKey]; exists {
				svc.Count++
			} else {
				serviceMap[serviceKey] = &models.ServiceInfo{
					Name:  serviceName,
					Port:  port.PortID,
					Count: 1,
				}
			}
		}
		
		if openPortCount > 0 {
			*hosts = append(*hosts, models.HostAnalysis{
				IPAddress:      ipAddress,
				OpenPortsCount: openPortCount,
				RiskLevel:      hostRiskLevel,
			})
		}
	}
}

// PortRisk represents the risk assessment of a port
type PortRisk struct {
	Level  string
	Reason string
}

// assessPortRisk determines the risk level of a port
func (ra *ReportAnalyzer) assessPortRisk(port, service string) PortRisk {
	// High risk ports and services
	highRiskPorts := map[string]string{
		"21":   "FTP - Unencrypted file transfer",
		"23":   "Telnet - Unencrypted remote access",
		"445":  "SMB - Common attack vector",
		"3389": "RDP - Remote desktop access",
		"5900": "VNC - Remote desktop access",
		"1433": "MSSQL - Database exposed",
		"3306": "MySQL - Database exposed",
		"5432": "PostgreSQL - Database exposed",
		"27017": "MongoDB - Database exposed",
		"6379": "Redis - Database exposed",
	}
	
	if reason, exists := highRiskPorts[port]; exists {
		return PortRisk{Level: "High", Reason: reason}
	}
	
	// Medium risk services
	mediumRiskServices := map[string]string{
		"ssh":      "SSH access exposed",
		"http":     "Unencrypted web traffic",
		"ftp":      "File transfer protocol",
		"smtp":     "Email server exposed",
		"pop3":     "Email retrieval exposed",
		"imap":     "Email access exposed",
		"mysql":    "Database service",
		"postgresql": "Database service",
	}
	
	serviceLower := strings.ToLower(service)
	if reason, exists := mediumRiskServices[serviceLower]; exists {
		return PortRisk{Level: "Medium", Reason: reason}
	}
	
	// HTTPS and other encrypted services are low risk
	if serviceLower == "https" || serviceLower == "ssl" {
		return PortRisk{Level: "Low", Reason: "Encrypted service"}
	}
	
	return PortRisk{Level: "Low", Reason: "Standard service"}
}

// generateVulnerabilities creates vulnerability entries based on findings
func (ra *ReportAnalyzer) generateVulnerabilities(ports []models.PortAnalysis, report *models.ScanReport) {
	vulnMap := make(map[string]*models.Vulnerability)
	
	for _, port := range ports {
		if port.RiskLevel == "High" {
			key := fmt.Sprintf("HIGH-%s-%s", port.Service, port.Port)
			
			if _, exists := vulnMap[key]; !exists {
				vuln := models.Vulnerability{
					ID:          fmt.Sprintf("VULN-%s-%s", strings.ToUpper(port.Service), port.Port),
					Title:       fmt.Sprintf("High Risk Service: %s on port %s", port.Service, port.Port),
					Severity:    "High",
					Description: port.RiskReason,
					AffectedPorts: []string{port.Port},
				}
				vulnMap[key] = &vuln
			} else {
				vulnMap[key].AffectedPorts = append(vulnMap[key].AffectedPorts, port.Port)
			}
		}
	}
	
	for _, vuln := range vulnMap {
		report.Vulnerabilities = append(report.Vulnerabilities, *vuln)
	}
}

// generateRecommendations creates security recommendations
func (ra *ReportAnalyzer) generateRecommendations(ports []models.PortAnalysis, report *models.ScanReport) {
	var recommendations []models.Recommendation
	
	// Check for unencrypted services
	hasHTTP := false
	hasFTP := false
	hasTelnet := false
	httpPorts := []string{}
	
	for _, port := range ports {
		switch strings.ToLower(port.Service) {
		case "http":
			hasHTTP = true
			httpPorts = append(httpPorts, port.Port)
		case "ftp":
			hasFTP = true
		case "telnet":
			hasTelnet = true
		}
	}
	
	if hasHTTP {
		recommendations = append(recommendations, models.Recommendation{
			Priority:      "High",
			Title:         "Use HTTPS Instead of HTTP",
			Description:   "Unencrypted HTTP traffic detected. All web traffic should be encrypted.",
			AffectedItems: httpPorts,
			Remediation:   "Configure SSL/TLS certificates and redirect all HTTP traffic to HTTPS",
		})
	}
	
	if hasFTP {
		recommendations = append(recommendations, models.Recommendation{
			Priority:      "High",
			Title:         "Replace FTP with SFTP or FTPS",
			Description:   "FTP transmits credentials in plain text",
			AffectedItems: []string{"21"},
			Remediation:   "Use SFTP (SSH File Transfer Protocol) or FTPS (FTP Secure) instead",
		})
	}
	
	if hasTelnet {
		recommendations = append(recommendations, models.Recommendation{
			Priority:      "Critical",
			Title:         "Disable Telnet - Use SSH",
			Description:   "Telnet is highly insecure and transmits all data in plain text",
			AffectedItems: []string{"23"},
			Remediation:   "Disable Telnet service and use SSH for remote access",
		})
	}
	
	// General recommendation about exposed services
	if len(ports) > 10 {
		recommendations = append(recommendations, models.Recommendation{
			Priority:      "Medium",
			Title:         "Minimize Attack Surface",
			Description:   fmt.Sprintf("Total of %d open ports detected. Each open port is a potential entry point.", len(ports)),
			AffectedItems: []string{"All open ports"},
			Remediation:   "Close unnecessary ports and disable unused services. Implement firewall rules.",
		})
	}
	
	report.Recommendations = recommendations
}

// calculateRiskScore calculates overall risk score (0-100)
func (ra *ReportAnalyzer) calculateRiskScore(report *models.ScanReport) int {
	score := 0
	
	// Base score from high risk ports
	score += report.Summary.HighRiskPorts * 15
	score += report.Summary.MediumRiskPorts * 5
	score += report.Summary.LowRiskPorts * 1
	
	// Additional score from vulnerabilities
	for _, vuln := range report.Vulnerabilities {
		switch vuln.Severity {
		case "Critical":
			score += 25
		case "High":
			score += 15
		case "Medium":
			score += 5
		}
	}
	
	// Cap at 100
	if score > 100 {
		score = 100
	}
	
	return score
}
