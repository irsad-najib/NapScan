package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"napscan-be/internal/repository"
	"napscan-be/internal/scanner"

	"github.com/google/uuid"
)

// ReportAggregator generates comprehensive security reports
type ReportAggregator struct {
	batchRepo *repository.BatchRepository
	vulnRepo  *repository.VulnerabilityRepository
}

// NewReportAggregator creates a new report aggregator
func NewReportAggregator(
	batchRepo *repository.BatchRepository,
	vulnRepo *repository.VulnerabilityRepository,
) *ReportAggregator {
	return &ReportAggregator{
		batchRepo: batchRepo,
		vulnRepo:  vulnRepo,
	}
}

// UnifiedReport represents a comprehensive security scan report
type UnifiedReport struct {
	BatchID           string                 `json:"batch_id"`
	GeneratedAt       time.Time              `json:"generated_at"`
	Summary           ReportSummary          `json:"summary"`
	VulnerabilityStats VulnerabilityStats     `json:"vulnerability_stats"`
	ToolCoverage      ToolCoverage           `json:"tool_coverage"`
	Vulnerabilities   []VulnerabilityDetail  `json:"vulnerabilities"`
	RiskAssessment    RiskAssessment         `json:"risk_assessment"`
	Recommendations   []string               `json:"recommendations"`
}

// ReportSummary provides high-level overview
type ReportSummary struct {
	Target              string        `json:"target"`
	ScanDuration        time.Duration `json:"scan_duration"`
	TotalTools          int           `json:"total_tools"`
	SuccessfulTools     int           `json:"successful_tools"`
	FailedTools         int           `json:"failed_tools"`
	TotalVulnerabilities int          `json:"total_vulnerabilities"`
	UniqueVulnerabilities int         `json:"unique_vulnerabilities"`
}

// VulnerabilityStats shows breakdown by severity
type VulnerabilityStats struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ToolCoverage shows which tools ran and their status
type ToolCoverage struct {
	ToolsExecuted []ToolExecutionInfo `json:"tools_executed"`
	ToolsFailed   []ToolExecutionInfo `json:"tools_failed"`
}

// ToolExecutionInfo contains execution details for a tool
type ToolExecutionInfo struct {
	ToolName          string        `json:"tool_name"`
	Status            string        `json:"status"`
	Duration          time.Duration `json:"duration"`
	VulnerabilitiesFound int        `json:"vulnerabilities_found"`
	ErrorMessage      string        `json:"error_message,omitempty"`
}

// VulnerabilityDetail represents a detailed vulnerability entry
type VulnerabilityDetail struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Severity        string                 `json:"severity"`
	SeverityScore   int                    `json:"severity_score"` // For sorting
	Description     string                 `json:"description"`
	AffectedAssets  []string               `json:"affected_assets"`
	SourceTools     []string               `json:"source_tools"` // Multiple tools may find same vuln
	Evidence        string                 `json:"evidence"`
	Remediation     string                 `json:"remediation"`
	CVE             string                 `json:"cve,omitempty"`
	CWE             string                 `json:"cwe,omitempty"`
	CVSS            float64                `json:"cvss,omitempty"`
	FirstDetected   time.Time              `json:"first_detected"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// RiskAssessment provides overall risk analysis
type RiskAssessment struct {
	OverallRiskScore  int     `json:"overall_risk_score"` // 0-100
	RiskLevel         string  `json:"risk_level"`         // low, medium, high, critical
	TopRisks          []string `json:"top_risks"`
	ComplianceImpact  string  `json:"compliance_impact"`
}

// GenerateReport creates a comprehensive unified report for a batch
func (a *ReportAggregator) GenerateReport(ctx context.Context, batchID uuid.UUID, userID string) (*UnifiedReport, error) {
	// Get batch information
	batch, err := a.batchRepo.GetBatchByID(ctx, batchID.String(), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get batch: %w", err)
	}
	if batch == nil {
		return nil, fmt.Errorf("batch not found")
	}
	
	// Get all scan jobs
	jobs, err := a.batchRepo.GetScanJobsByBatchID(ctx, batch.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan jobs: %w", err)
	}
	
	// Get all vulnerabilities (excluding duplicates)
	vulnerabilities, err := a.vulnRepo.GetVulnerabilitiesByBatchID(ctx, batch.ID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %w", err)
	}
	
	// Build report
	report := &UnifiedReport{
		BatchID:     batch.BatchID,
		GeneratedAt: time.Now(),
	}
	
	// Build summary
	report.Summary = a.buildSummary(batch, jobs, vulnerabilities)
	
	// Build vulnerability stats
	report.VulnerabilityStats = a.buildVulnerabilityStats(vulnerabilities)
	
	// Build tool coverage
	report.ToolCoverage = a.buildToolCoverage(jobs, vulnerabilities)
	
	// Build vulnerability details
	report.Vulnerabilities = a.buildVulnerabilityDetails(vulnerabilities)
	
	// Build risk assessment
	report.RiskAssessment = a.buildRiskAssessment(report.VulnerabilityStats, vulnerabilities)
	
	// Generate recommendations
	report.Recommendations = a.generateRecommendations(report)
	
	return report, nil
}

// buildSummary creates the summary section
func (a *ReportAggregator) buildSummary(batch *repository.Batch, jobs []repository.ScanJob, vulns []repository.DBVulnerability) ReportSummary {
	successCount := 0
	failedCount := 0
	
	for _, job := range jobs {
		if job.Status == scanner.StatusSuccess {
			successCount++
		} else if job.Status == scanner.StatusFailed {
			failedCount++
		}
	}
	
	var duration time.Duration
	if batch.CompletedAt != nil {
		duration = batch.CompletedAt.Sub(batch.CreatedAt)
	}
	
	return ReportSummary{
		Target:                batch.Target,
		ScanDuration:          duration,
		TotalTools:            len(jobs),
		SuccessfulTools:       successCount,
		FailedTools:           failedCount,
		TotalVulnerabilities:  len(vulns),
		UniqueVulnerabilities: len(vulns), // Already filtered for duplicates
	}
}

// buildVulnerabilityStats creates vulnerability statistics
func (a *ReportAggregator) buildVulnerabilityStats(vulns []repository.DBVulnerability) VulnerabilityStats {
	stats := VulnerabilityStats{}
	
	for _, vuln := range vulns {
		switch vuln.Severity {
		case "critical":
			stats.Critical++
		case "high":
			stats.High++
		case "medium":
			stats.Medium++
		case "low":
			stats.Low++
		case "info":
			stats.Info++
		}
	}
	
	return stats
}

// buildToolCoverage creates tool coverage information
func (a *ReportAggregator) buildToolCoverage(jobs []repository.ScanJob, vulns []repository.DBVulnerability) ToolCoverage {
	coverage := ToolCoverage{
		ToolsExecuted: []ToolExecutionInfo{},
		ToolsFailed:   []ToolExecutionInfo{},
	}
	
	// Count vulnerabilities per tool
	vulnCount := make(map[string]int)
	for _, vuln := range vulns {
		vulnCount[vuln.SourceTool]++
	}
	
	for _, job := range jobs {
		var duration time.Duration
		if job.StartTime != nil && job.EndTime != nil {
			duration = job.EndTime.Sub(*job.StartTime)
		}
		
		info := ToolExecutionInfo{
			ToolName:             job.ToolName,
			Status:               string(job.Status),
			Duration:             duration,
			VulnerabilitiesFound: vulnCount[job.ToolName],
			ErrorMessage:         job.ErrorMessage,
		}
		
		if job.Status == scanner.StatusSuccess {
			coverage.ToolsExecuted = append(coverage.ToolsExecuted, info)
		} else if job.Status == scanner.StatusFailed {
			coverage.ToolsFailed = append(coverage.ToolsFailed, info)
		}
	}
	
	return coverage
}

// buildVulnerabilityDetails creates detailed vulnerability list
func (a *ReportAggregator) buildVulnerabilityDetails(vulns []repository.DBVulnerability) []VulnerabilityDetail {
	details := make([]VulnerabilityDetail, 0, len(vulns))
	
	for _, vuln := range vulns {
		var affectedAssets []string
		json.Unmarshal(vuln.AffectedAsset, &affectedAssets)
		
		var metadata map[string]interface{}
		json.Unmarshal(vuln.Metadata, &metadata)
		
		cvss := 0.0
		if vuln.CVSS != nil {
			cvss = *vuln.CVSS
		}
		
		detail := VulnerabilityDetail{
			ID:             vuln.ID.String(),
			Title:          vuln.Title,
			Severity:       vuln.Severity,
			SeverityScore:  getSeverityScore(vuln.Severity),
			Description:    vuln.Description,
			AffectedAssets: affectedAssets,
			SourceTools:    []string{vuln.SourceTool},
			Evidence:       vuln.Evidence,
			Remediation:    vuln.Remediation,
			CVE:            vuln.CVE,
			CWE:            vuln.CWE,
			CVSS:           cvss,
			Metadata:       metadata,
		}
		
		details = append(details, detail)
	}
	
	// Sort by severity (critical first)
	sort.Slice(details, func(i, j int) bool {
		return details[i].SeverityScore > details[j].SeverityScore
	})
	
	return details
}

// buildRiskAssessment creates risk assessment
func (a *ReportAggregator) buildRiskAssessment(stats VulnerabilityStats, vulns []repository.DBVulnerability) RiskAssessment {
	// Calculate risk score (0-100)
	riskScore := stats.Critical*20 + stats.High*10 + stats.Medium*5 + stats.Low*2 + stats.Info*1
	if riskScore > 100 {
		riskScore = 100
	}
	
	// Determine risk level
	riskLevel := "low"
	if stats.Critical > 0 {
		riskLevel = "critical"
	} else if stats.High > 0 || riskScore > 50 {
		riskLevel = "high"
	} else if stats.Medium > 0 || riskScore > 20 {
		riskLevel = "medium"
	}
	
	// Identify top risks
	topRisks := []string{}
	if stats.Critical > 0 {
		topRisks = append(topRisks, fmt.Sprintf("%d critical vulnerabilities require immediate attention", stats.Critical))
	}
	if stats.High > 0 {
		topRisks = append(topRisks, fmt.Sprintf("%d high-severity vulnerabilities found", stats.High))
	}
	
	// Assess compliance impact
	complianceImpact := "Low compliance risk"
	if stats.Critical > 0 || stats.High > 3 {
		complianceImpact = "High compliance risk - immediate remediation required"
	} else if stats.High > 0 || stats.Medium > 5 {
		complianceImpact = "Moderate compliance risk - plan remediation timeline"
	}
	
	return RiskAssessment{
		OverallRiskScore: riskScore,
		RiskLevel:        riskLevel,
		TopRisks:         topRisks,
		ComplianceImpact: complianceImpact,
	}
}

// generateRecommendations creates actionable recommendations
func (a *ReportAggregator) generateRecommendations(report *UnifiedReport) []string {
	recommendations := []string{}
	
	if report.VulnerabilityStats.Critical > 0 {
		recommendations = append(recommendations, 
			"URGENT: Address all critical vulnerabilities within 24 hours",
			"Implement incident response procedures for critical findings")
	}
	
	if report.VulnerabilityStats.High > 0 {
		recommendations = append(recommendations, 
			"High priority: Remediate high-severity vulnerabilities within 7 days")
	}
	
	if report.Summary.FailedTools > 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("Warning: %d security tools failed to execute - verify tool configuration", report.Summary.FailedTools))
	}
	
	if report.VulnerabilityStats.Medium > 5 {
		recommendations = append(recommendations, 
			"Consider implementing automated vulnerability scanning in CI/CD pipeline")
	}
	
	recommendations = append(recommendations,
		"Schedule regular security scans (weekly recommended)",
		"Implement a vulnerability management program",
		"Conduct security awareness training for development team")
	
	return recommendations
}

// getSeverityScore converts severity to numeric score for sorting
func getSeverityScore(severity string) int {
	switch severity {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
