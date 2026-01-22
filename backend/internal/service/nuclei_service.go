package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"napscan-be/internal/models"
)

type NucleiService struct{}

func NewNucleiService() *NucleiService {
	return &NucleiService{}
}

// RunNucleiAsync is the async scan function following the contract
func RunNucleiAsync(ctx context.Context, taskID string, manager *ScanManager) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	log.Printf("[NUCLEI_ASYNC] Starting async scan for task=%s target=%s", taskID, target)

	// Update to running
	manager.UpdateProgress(taskID, 0, models.StatusRunning)

	// Phase 1: Init (0-5%)
	manager.UpdateProgress(taskID, 5, models.StatusRunning)

	tmpFile := filepath.Join(os.TempDir(), "nuclei_"+time.Now().Format("20060102150405")+".jsonl")
	defer os.Remove(tmpFile)

	// Build nuclei command with context
	cmd := exec.CommandContext(ctx,
		"nuclei",
		"-target", target,
		"-jsonl",
		"-o", tmpFile,
		"-silent",
		"-nc",
	)

	// Capture stdout for progress tracking
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		manager.Fail(taskID, fmt.Errorf("failed to create stdout pipe: %w", err))
		return err
	}

	// Phase 2: Start scan (5-10%)
	manager.UpdateProgress(taskID, 10, models.StatusRunning)

	log.Printf("[NUCLEI_ASYNC] Starting nuclei process")
	if err := cmd.Start(); err != nil {
		log.Printf("[NUCLEI_ASYNC] Failed to start nuclei: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to start nuclei: %w", err))
		return err
	}

	// Phase 3: Monitor progress (10-90%)
	// Parse stdout line-by-line for progress
	currentProgress := 10
	outputLines := make(chan string, 100)

	// Read stdout in goroutine
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			outputLines <- scanner.Text()
		}
		close(outputLines)
	}()

	// Wait for command to finish
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- cmd.Wait()
	}()

	progressTicker := time.NewTicker(3 * time.Second)
	defer progressTicker.Stop()

	scanFinished := false
	var scanErr error
	findingCount := 0

	for !scanFinished {
		select {
		case <-ctx.Done():
			// Context cancelled - kill the process
			log.Printf("[NUCLEI_ASYNC] Context cancelled for task=%s, killing process", taskID)
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			manager.UpdateProgress(taskID, currentProgress, models.StatusStopped)
			return ctx.Err()

		case err := <-doneChan:
			scanFinished = true
			scanErr = err

		case line, ok := <-outputLines:
			if ok && strings.TrimSpace(line) != "" {
				findingCount++
				// Increment progress per finding, but more gradually
				// Start with 3%, then 2%, then 1% as we find more
				if currentProgress < 90 {
					var increment int
					if findingCount <= 5 {
						increment = 3 // First 5 findings: 3% each
					} else if findingCount <= 15 {
						increment = 2 // Next 10 findings: 2% each
					} else {
						increment = 1 // After that: 1% each
					}
					
					currentProgress += increment
					if currentProgress > 90 {
						currentProgress = 90
					}
					manager.UpdateProgress(taskID, currentProgress, models.StatusRunning)
					log.Printf("[NUCLEI_ASYNC] Progress update: %d%% (findings: %d)", currentProgress, findingCount)
				}
			}

		case <-progressTicker.C:
			// Only increment if no findings yet (stuck scanning)
			if currentProgress < 30 && findingCount == 0 {
				currentProgress += 3
				manager.UpdateProgress(taskID, currentProgress, models.StatusRunning)
				log.Printf("[NUCLEI_ASYNC] Progress bump (scanning): %d%%", currentProgress)
			}
		}
	}

	// Check if scan failed
	if scanErr != nil {
		log.Printf("[NUCLEI_ASYNC] Scan failed: %v", scanErr)
		manager.Fail(taskID, fmt.Errorf("nuclei execution failed: %w", scanErr))
		return scanErr
	}

	// Phase 4: Parse results (90-95%)
	manager.UpdateProgress(taskID, 90, models.StatusRunning)

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("[NUCLEI_ASYNC] Failed to read output file: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to read nuclei output: %w", err))
		return err
	}

	trimmed := strings.TrimSpace(string(jsonData))
	if trimmed == "" {
		log.Printf("[NUCLEI_ASYNC] No vulnerabilities found")
		manager.Complete(taskID, []map[string]interface{}{})
		return nil
	}

	lines := strings.Split(trimmed, "\n")
	log.Printf("[NUCLEI_ASYNC] Parsing %d result lines", len(lines))
	results := make([]map[string]interface{}, 0, len(lines))
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("[NUCLEI_ASYNC] Failed to parse line: %v", err)
			manager.Fail(taskID, fmt.Errorf("failed to parse nuclei jsonl: %w, line: %s", err, line))
			return err
		}
		results = append(results, obj)
	}

	// Phase 5: Save report (95-100%)
	manager.UpdateProgress(taskID, 95, models.StatusRunning)

	// Complete the task
	manager.Complete(taskID, results)
	log.Printf("[NUCLEI_ASYNC] Scan completed successfully for task=%s with %d results", taskID, len(results))

	return nil
}

// Legacy ExecuteScan for backward compatibility
func (s *NucleiService) ExecuteScan(ctx context.Context, target string) ([]map[string]interface{}, error) {
	log.Printf("[NUCLEI_SERVICE] Starting scan on target=%s", target)
	tmpFile := filepath.Join(os.TempDir(), "nuclei_"+time.Now().Format("20060102150405")+".jsonl")
	defer os.Remove(tmpFile)

	cmd := exec.CommandContext(ctx,
		"nuclei",
		"-target", target,
		"-jsonl",
		"-o", tmpFile,
		"-silent",
		"-nc",
	)

	log.Printf("[NUCLEI_SERVICE] Executing nuclei command")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[NUCLEI_SERVICE] Nuclei execution failed: %v, output: %s", err, string(output))
		return nil, fmt.Errorf("nuclei execution failed: %v, output: %s", err, string(output))
	}
	log.Printf("[NUCLEI_SERVICE] Nuclei execution completed")

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("[NUCLEI_SERVICE] Failed to read output file: %v", err)
		return nil, fmt.Errorf("failed to read nuclei output: %w", err)
	}

	trimmed := strings.TrimSpace(string(jsonData))
	if trimmed == "" {
		log.Printf("[NUCLEI_SERVICE] No vulnerabilities found")
		return []map[string]interface{}{}, nil
	}

	lines := strings.Split(trimmed, "\n")
	log.Printf("[NUCLEI_SERVICE] Parsing %d result lines", len(lines))
	results := make([]map[string]interface{}, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("[NUCLEI_SERVICE] Failed to parse line: %v", err)
			return nil, fmt.Errorf("failed to parse nuclei jsonl: %w, line: %s", err, line)
		}
		results = append(results, obj)
	}

	log.Printf("[NUCLEI_SERVICE] Scan completed with %d results", len(results))
	return results, nil
}
