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

type NucleiService struct {
	intelligence *IntelligenceService
}

func NewNucleiService(intelligence *IntelligenceService) *NucleiService {
	return &NucleiService{
		intelligence: intelligence,
	}
}

// RunNucleiAsync is the async scan function following the contract
func (s *NucleiService) RunNucleiAsync(ctx context.Context, taskID string, manager *ScanManager, tenantID string) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	log.Printf("[NUCLEI_ASYNC] Starting async scan for task=%s target=%s", taskID, target)

	manager.UpdateProgress(taskID, 0, models.StatusRunning)
	manager.UpdateProgress(taskID, 5, models.StatusRunning)

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

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		manager.Fail(taskID, fmt.Errorf("failed to create stdout pipe: %w", err))
		return err
	}

	manager.UpdateProgress(taskID, 10, models.StatusRunning)

	log.Printf("[NUCLEI_ASYNC] Starting nuclei process")
	if err := cmd.Start(); err != nil {
		log.Printf("[NUCLEI_ASYNC] Failed to start nuclei: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to start nuclei: %w", err))
		return err
	}

	// Progress tracking
	currentProgress := 10
	outputLines := make(chan string, 100)

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			outputLines <- scanner.Text()
		}
		close(outputLines)
	}()

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
				if currentProgress < 90 {
					var increment int
					if findingCount <= 5 {
						increment = 3
					} else if findingCount <= 15 {
						increment = 2
					} else {
						increment = 1
					}

					currentProgress += increment
					if currentProgress > 90 {
						currentProgress = 90
					}
					manager.UpdateProgress(taskID, currentProgress, models.StatusRunning)
				}
			}

		case <-progressTicker.C:
			if currentProgress < 30 && findingCount == 0 {
				currentProgress += 3
				manager.UpdateProgress(taskID, currentProgress, models.StatusRunning)
			}
		}
	}

	if scanErr != nil {
		log.Printf("[NUCLEI_ASYNC] Scan failed: %v", scanErr)
		manager.Fail(taskID, fmt.Errorf("nuclei execution failed: %w", scanErr))
		return scanErr
	}

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
	var resultsInterface []interface{}

	// Process findings via Intelligence Service
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}

		// Legacy result storage (keeping map slice for internal logic if needed, but we output interface slice)
		results = append(results, obj)
		resultsInterface = append(resultsInterface, obj)
	}

	manager.UpdateProgress(taskID, 95, models.StatusRunning)
	manager.Complete(taskID, resultsInterface)
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

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read nuclei output: %w", err)
	}

	trimmed := strings.TrimSpace(string(jsonData))
	if trimmed == "" {
		return []map[string]interface{}{}, nil
	}

	lines := strings.Split(trimmed, "\n")
	results := make([]map[string]interface{}, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		results = append(results, obj)
	}

	return results, nil
}
