package service

import (
	"context"
	"fmt"
	"log"
	"napscan-be/internal/models"
	"strings"
	"time"
)

// StopTask sends a stop command to the OpenVAS daemon for a specific task.
// This method is added here to avoid modifying openvas_service.go directly,
// leveraging Go's package-level method definition capabilities.
func (s *OpenVASService) StopTask(ctx context.Context, taskID string) error {
	log.Printf("[OPENVAS_ASYNC] Stopping task %s", taskID)
	stopTaskXML := fmt.Sprintf(`<stop_task task_id="%s"/>`, taskID)
	out, err := s.RunGVMCLI(ctx, stopTaskXML)
	if err != nil {
		log.Printf("[OPENVAS_ASYNC] Failed to stop task: %v", err)
		return fmt.Errorf("failed to stop task: %w, output: %s", err, string(out))
	}
	log.Printf("[OPENVAS_ASYNC] Task stop command sent successfully")
	return nil
}

// ResumeOpenVASAsync resumes a stopped OpenVAS scan.
func ResumeOpenVASAsync(ctx context.Context, taskID string, manager *ScanManager, service *OpenVASService) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	openvasTaskID := task.ExternalID
	if openvasTaskID == "" {
		return fmt.Errorf("cannot resume: missing OpenVAS Task ID (external_id)")
	}

	log.Printf("[OPENVAS_ASYNC] Resuming scan for task=%s openvas_id=%s", taskID, openvasTaskID)

	// Send Resume Command
	resumeXML := fmt.Sprintf(`<resume_task task_id="%s"/>`, openvasTaskID)
	out, err := service.RunGVMCLI(ctx, resumeXML)
	if err != nil {
		log.Printf("[OPENVAS_ASYNC] Failed to resume task: %v", err)
		return fmt.Errorf("failed to resume task: %w, output: %s", err, string(out))
	}

	// Re-enter monitoring loop
	manager.UpdateProgress(taskID, 10, models.StatusRunning)
	return monitorOpenVASScan(ctx, taskID, openvasTaskID, manager, service)
}

// monitorOpenVASScan handles the polling loop for OpenVAS scans
func monitorOpenVASScan(ctx context.Context, taskID string, openvasTaskID string, manager *ScanManager, service *OpenVASService) error {
	// Poll every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Context cancelled - Stop the scan
			log.Printf("[OPENVAS_ASYNC] Context cancelled for task=%s, stopping OpenVAS task %s", taskID, openvasTaskID)

			// Use a fresh context for the stop command as the parent context is cancelled
			stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := service.StopTask(stopCtx, openvasTaskID); err != nil {
				log.Printf("[OPENVAS_ASYNC] Error stopping task: %v", err)
			}

			manager.UpdateProgress(taskID, 0, models.StatusStopped)
			return ctx.Err()

		case <-ticker.C:
			// Check status
			status, err := service.GetTaskStatus(ctx, openvasTaskID)
			if err != nil {
				log.Printf("[OPENVAS_ASYNC] Failed to get status: %v", err)
				continue
			}

			log.Printf("[OPENVAS_ASYNC] Task %s status: %s, progress: %s", openvasTaskID, status.Status, status.Progress)

			// Parse progress
			progress := 0
			fmt.Sscanf(status.Progress, "%d", &progress)

			// Map OpenVAS progress (0-100) to our scale (10-90 for running)
			mappedProgress := 10 + (progress * 80 / 100)

			// Handle Status
			if status.Status == "Done" {
				goto Complete
			} else if status.Status == "Stopped" {
				manager.UpdateProgress(taskID, mappedProgress, models.StatusStopped)
				return nil
			} else if strings.Contains(strings.ToLower(status.Status), "fail") {
				err := fmt.Errorf("openvas scan failed with status: %s", status.Status)
				manager.Fail(taskID, err)
				return err
			}

			manager.UpdateProgress(taskID, mappedProgress, models.StatusRunning)
		}
	}

Complete:
	// Phase 3: Get Results (90-95%)
	manager.UpdateProgress(taskID, 90, models.StatusRunning)

	status, err := service.GetTaskStatus(ctx, openvasTaskID)
	if err != nil {
		manager.Fail(taskID, fmt.Errorf("failed to get final status for report ID: %w", err))
		return err
	}

	reportID := status.LastReport.Report.ID
	if reportID == "" {
		// If no report ID, maybe it failed silently or was empty?
		// Try listing reports for task?
		// For now fail.
		manager.Fail(taskID, fmt.Errorf("no report ID found for completed task"))
		return fmt.Errorf("no report ID")
	}

	report, err := service.GetScanReport(ctx, reportID)
	if err != nil {
		manager.Fail(taskID, fmt.Errorf("failed to get report: %w", err))
		return err
	}

	// Phase 4: Save & Finish (95-100%)
	manager.UpdateProgress(taskID, 95, models.StatusRunning)

	manager.Complete(taskID, report)
	log.Printf("[OPENVAS_ASYNC] Scan completed successfully for task=%s", taskID)

	return nil
}

// RunOpenVASAsync handles the asynchronous execution of an OpenVAS scan.
// It manages the scan lifecycle, including starting, polling for progress,
// handling cancellation, and saving results.
func RunOpenVASAsync(ctx context.Context, taskID string, manager *ScanManager, service *OpenVASService) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	batchID := task.BatchID
	log.Printf("[OPENVAS_ASYNC] Starting async scan for task=%s target=%s", taskID, target)

	// Update to running
	manager.UpdateProgress(taskID, 0, models.StatusRunning)

	// Phase 1: Start Scan (0-10%)
	// Note: StartScan in openvas_service.go currently handles target creation, task creation, and starting.
	// It returns a map with taskID. We need to extract that.

	// Ensure we have a context that is NOT the task context for the start operation
	// because if task context is cancelled, we still want to be able to stop the scan if it started.
	// Actually, if task context is cancelled, we shouldn't start.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	startResult, err := service.StartScan(ctx, target, batchID)
	if err != nil {
		log.Printf("[OPENVAS_ASYNC] Failed to start scan: %v", err)
		manager.Fail(taskID, err)
		return err
	}

	// Extract actual OpenVAS Task ID from result
	openvasTaskID, ok := startResult["taskID"].(string)
	if !ok || openvasTaskID == "" {
		err := fmt.Errorf("failed to extract OpenVAS Task ID from start result")
		manager.Fail(taskID, err)
		return err
	}

	// Save External ID
	manager.UpdateExternalID(taskID, openvasTaskID)

	log.Printf("[OPENVAS_ASYNC] OpenVAS scan started with ID: %s", openvasTaskID)
	manager.UpdateProgress(taskID, 10, models.StatusRunning)

	return monitorOpenVASScan(ctx, taskID, openvasTaskID, manager, service)
}
