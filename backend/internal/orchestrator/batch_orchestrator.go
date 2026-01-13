package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"napscan-be/internal/repository"
	"napscan-be/internal/scanner"

	"github.com/google/uuid"
)

// BatchOrchestrator manages batch scan execution
type BatchOrchestrator struct {
	registry   scanner.ScannerRegistry
	batchRepo  *repository.BatchRepository
	vulnRepo   *repository.VulnerabilityRepository
	maxWorkers int
}

// NewBatchOrchestrator creates a new batch orchestrator
func NewBatchOrchestrator(
	registry scanner.ScannerRegistry,
	batchRepo *repository.BatchRepository,
	vulnRepo *repository.VulnerabilityRepository,
) *BatchOrchestrator {
	return &BatchOrchestrator{
		registry:   registry,
		batchRepo:  batchRepo,
		vulnRepo:   vulnRepo,
		maxWorkers: 10, // Maximum concurrent scans
	}
}

// BatchRequest represents a scan batch request
type BatchRequest struct {
	UserID      string                 `json:"user_id"`
	BatchID     string                 `json:"batch_id"`
	Target      string                 `json:"target"`
	ScanType    ScanType               `json:"scan_type"` // all, single, custom
	ToolNames   []string               `json:"tool_names,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
}

// ScanType defines the type of scan
type ScanType string

const (
	ScanTypeAll    ScanType = "all"    // Run all available scanners
	ScanTypeSingle ScanType = "single" // Run a single scanner
	ScanTypeCustom ScanType = "custom" // Run selected scanners
)

// BatchResult contains the results of a batch execution
type BatchResult struct {
	BatchID           string                      `json:"batch_id"`
	Status            string                      `json:"status"`
	JobResults        []JobResult                 `json:"job_results"`
	TotalJobs         int                         `json:"total_jobs"`
	SuccessfulJobs    int                         `json:"successful_jobs"`
	FailedJobs        int                         `json:"failed_jobs"`
	TotalVulns        int                         `json:"total_vulnerabilities"`
	VulnsBySeverity   map[string]int              `json:"vulnerabilities_by_severity"`
	StartTime         time.Time                   `json:"start_time"`
	EndTime           time.Time                   `json:"end_time"`
	Duration          time.Duration               `json:"duration"`
}

// JobResult contains the result of a single scan job
type JobResult struct {
	ToolName         string                  `json:"tool_name"`
	Status           scanner.ScanStatus      `json:"status"`
	VulnCount        int                     `json:"vulnerability_count"`
	Vulnerabilities  []scanner.Vulnerability `json:"vulnerabilities,omitempty"`
	ErrorMessage     string                  `json:"error_message,omitempty"`
	Duration         time.Duration           `json:"duration"`
}

// ExecuteBatch creates and executes a batch of scans
func (o *BatchOrchestrator) ExecuteBatch(ctx context.Context, req *BatchRequest) (*BatchResult, error) {
	startTime := time.Now()
	
	// Validate request
	if err := o.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	
	// Determine which scanners to run
	toolNames, err := o.getToolNames(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get tool names: %w", err)
	}
	
	// Create batch record
	batch := &repository.Batch{
		BatchID:          req.BatchID,
		UserID:           req.UserID,
		Target:           req.Target,
		ExpectedJobCount: len(toolNames),
		Status:           "processing",
	}
	
	if err := o.batchRepo.CreateBatch(ctx, batch); err != nil {
		return nil, fmt.Errorf("failed to create batch: %w", err)
	}
	
	// Create scan jobs
	jobs := make([]*repository.ScanJob, 0, len(toolNames))
	for _, toolName := range toolNames {
		configJSON, _ := json.Marshal(req.Options)
		job := &repository.ScanJob{
			BatchID:  batch.ID,
			ToolName: toolName,
			Status:   scanner.StatusPending,
			Target:   req.Target,
			Config:   configJSON,
		}
		
		if err := o.batchRepo.CreateScanJob(ctx, job); err != nil {
			log.Printf("Failed to create scan job for %s: %v", toolName, err)
			continue
		}
		
		jobs = append(jobs, job)
	}
	
	// Execute scans in parallel
	results := o.executeJobsParallel(ctx, req, jobs)
	
	// Process results and save vulnerabilities
	totalVulns := 0
	vulnStats := make(map[string]int)
	
	for _, result := range results {
		if result.Status == scanner.StatusSuccess && len(result.Vulnerabilities) > 0 {
			// Save vulnerabilities to database
			dbVulns := o.convertToDBVulnerabilities(batch.ID, result)
			if err := o.vulnRepo.BulkCreateVulnerabilities(ctx, dbVulns); err != nil {
				log.Printf("Failed to save vulnerabilities for %s: %v", result.ToolName, err)
			} else {
				totalVulns += len(result.Vulnerabilities)
				
				// Count by severity
				for _, vuln := range result.Vulnerabilities {
					vulnStats[string(vuln.Severity)]++
				}
			}
		}
	}
	
	// Update batch status
	batchStatus := "completed"
	allFailed := true
	for _, result := range results {
		if result.Status == scanner.StatusSuccess {
			allFailed = false
			break
		}
	}
	
	if allFailed {
		batchStatus = "failed"
	}
	
	if err := o.batchRepo.UpdateBatchStatus(ctx, batch.ID, batchStatus); err != nil {
		log.Printf("Failed to update batch status: %v", err)
	}
	
	// Calculate statistics
	successCount := 0
	failedCount := 0
	for _, result := range results {
		if result.Status == scanner.StatusSuccess {
			successCount++
		} else if result.Status == scanner.StatusFailed {
			failedCount++
		}
	}
	
	return &BatchResult{
		BatchID:         req.BatchID,
		Status:          batchStatus,
		JobResults:      results,
		TotalJobs:       len(jobs),
		SuccessfulJobs:  successCount,
		FailedJobs:      failedCount,
		TotalVulns:      totalVulns,
		VulnsBySeverity: vulnStats,
		StartTime:       startTime,
		EndTime:         time.Now(),
		Duration:        time.Since(startTime),
	}, nil
}

// executeJobsParallel runs scan jobs in parallel with worker pool
func (o *BatchOrchestrator) executeJobsParallel(ctx context.Context, req *BatchRequest, jobs []*repository.ScanJob) []JobResult {
	var wg sync.WaitGroup
	jobChan := make(chan *repository.ScanJob, len(jobs))
	resultChan := make(chan JobResult, len(jobs))
	
	// Start worker pool
	workerCount := min(o.maxWorkers, len(jobs))
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go o.worker(ctx, req, jobChan, resultChan, &wg)
	}
	
	// Send jobs to workers
	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)
	
	// Wait for all workers to finish
	wg.Wait()
	close(resultChan)
	
	// Collect results
	results := make([]JobResult, 0, len(jobs))
	for result := range resultChan {
		results = append(results, result)
	}
	
	return results
}

// worker processes scan jobs
func (o *BatchOrchestrator) worker(ctx context.Context, req *BatchRequest, jobs <-chan *repository.ScanJob, results chan<- JobResult, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for job := range jobs {
		result := o.executeScanJob(ctx, req, job)
		results <- result
	}
}

// executeScanJob executes a single scan job
func (o *BatchOrchestrator) executeScanJob(ctx context.Context, req *BatchRequest, job *repository.ScanJob) JobResult {
	startTime := time.Now()
	result := JobResult{
		ToolName: job.ToolName,
		Status:   scanner.StatusRunning,
	}
	
	// Update job status to running
	job.Status = scanner.StatusRunning
	job.StartTime = &startTime
	o.batchRepo.UpdateScanJob(ctx, job)
	
	// Get scanner from registry
	scannerInstance, err := o.registry.Get(job.ToolName)
	if err != nil {
		result.Status = scanner.StatusFailed
		result.ErrorMessage = fmt.Sprintf("Scanner not found: %v", err)
		o.updateJobWithError(ctx, job, result.ErrorMessage, startTime)
		result.Duration = time.Since(startTime)
		return result
	}
	
	// Create scan config
	timeout := req.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute // Default timeout
	}
	
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	scanConfig := scanner.ScanConfig{
		Target:  req.Target,
		Options: req.Options,
		Timeout: timeout,
		UserID:  req.UserID,
	}
	
	// Execute scan
	rawResult, err := scannerInstance.Execute(scanCtx, scanConfig)
	if err != nil {
		result.Status = scanner.StatusFailed
		result.ErrorMessage = fmt.Sprintf("Scan execution failed: %v", err)
		o.updateJobWithError(ctx, job, result.ErrorMessage, startTime)
		result.Duration = time.Since(startTime)
		return result
	}
	
	// Normalize results to vulnerabilities
	vulnerabilities, err := scannerInstance.Normalize(rawResult)
	if err != nil {
		log.Printf("Failed to normalize results for %s: %v", job.ToolName, err)
		vulnerabilities = []scanner.Vulnerability{} // Continue with empty vulns
	}
	
	// Update job with success
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	durationMs := duration.Milliseconds()
	
	rawResultJSON, _ := json.Marshal(rawResult)
	job.Status = scanner.StatusSuccess
	job.EndTime = &endTime
	job.DurationMs = &durationMs
	job.RawResult = rawResultJSON
	
	if err := o.batchRepo.UpdateScanJob(ctx, job); err != nil {
		log.Printf("Failed to update scan job: %v", err)
	}
	
	result.Status = scanner.StatusSuccess
	result.VulnCount = len(vulnerabilities)
	result.Vulnerabilities = vulnerabilities
	result.Duration = duration
	
	return result
}

// updateJobWithError updates a job with error information
func (o *BatchOrchestrator) updateJobWithError(ctx context.Context, job *repository.ScanJob, errMsg string, startTime time.Time) {
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	durationMs := duration.Milliseconds()
	
	job.Status = scanner.StatusFailed
	job.EndTime = &endTime
	job.DurationMs = &durationMs
	job.ErrorMessage = errMsg
	
	if err := o.batchRepo.UpdateScanJob(ctx, job); err != nil {
		log.Printf("Failed to update scan job: %v", err)
	}
}

// validateRequest validates the batch request
func (o *BatchOrchestrator) validateRequest(req *BatchRequest) error {
	if req.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	if req.BatchID == "" {
		return fmt.Errorf("batch_id is required")
	}
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	
	switch req.ScanType {
	case ScanTypeSingle:
		if len(req.ToolNames) != 1 {
			return fmt.Errorf("single scan requires exactly one tool name")
		}
	case ScanTypeCustom:
		if len(req.ToolNames) == 0 {
			return fmt.Errorf("custom scan requires at least one tool name")
		}
	case ScanTypeAll:
		// All is valid
	default:
		return fmt.Errorf("invalid scan type: %s", req.ScanType)
	}
	
	return nil
}

// getToolNames determines which tools to run based on scan type
func (o *BatchOrchestrator) getToolNames(req *BatchRequest) ([]string, error) {
	switch req.ScanType {
	case ScanTypeAll:
		return o.registry.List(), nil
	case ScanTypeSingle, ScanTypeCustom:
		// Validate that requested tools exist
		for _, toolName := range req.ToolNames {
			if _, err := o.registry.Get(toolName); err != nil {
				return nil, fmt.Errorf("tool %s not found: %w", toolName, err)
			}
		}
		return req.ToolNames, nil
	default:
		return nil, fmt.Errorf("invalid scan type")
	}
}

// convertToDBVulnerabilities converts scanner vulnerabilities to DB format
func (o *BatchOrchestrator) convertToDBVulnerabilities(batchID uuid.UUID, result JobResult) []repository.DBVulnerability {
	dbVulns := make([]repository.DBVulnerability, 0, len(result.Vulnerabilities))
	
	for _, vuln := range result.Vulnerabilities {
		affectedAssetJSON, _ := json.Marshal(vuln.AffectedAsset)
		metadataJSON, _ := json.Marshal(vuln.Metadata)
		
		dbVuln := repository.DBVulnerability{
			BatchID:       batchID,
			Title:         vuln.Title,
			Severity:      string(vuln.Severity),
			Description:   vuln.Description,
			AffectedAsset: affectedAssetJSON,
			SourceTool:    vuln.SourceTool,
			Evidence:      vuln.Evidence,
			Remediation:   vuln.Remediation,
			CVE:           vuln.CVE,
			CWE:           vuln.CWE,
			CVSS:          &vuln.CVSS,
			Metadata:      metadataJSON,
			Fingerprint:   repository.GenerateFingerprint(&vuln),
		}
		
		dbVulns = append(dbVulns, dbVuln)
	}
	
	return dbVulns
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
