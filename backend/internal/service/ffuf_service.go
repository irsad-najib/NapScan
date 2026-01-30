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

type FfufService struct{}

func NewFfufService() *FfufService {
	return &FfufService{}
}

// RunFfufAsync is the async scan function following the contract
// func RunX(ctx context.Context, taskID string, manager *ScanManager) error
func RunFfufAsync(ctx context.Context, taskID string, manager *ScanManager) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	log.Printf("[FFUF_ASYNC] Starting async scan for task=%s target=%s", taskID, target)

	// Update to running
	manager.UpdateProgress(taskID, 0, models.StatusRunning)

	// Ensure URL has protocol
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
		log.Printf("[FFUF_ASYNC] Added https:// prefix, new target=%s", target)
	}

	// Phase 1: Init (0-5%)
	manager.UpdateProgress(taskID, 5, models.StatusRunning)

	// Initialize stealth configuration
	stealthConfig := NewStealthConfig()
	randomUA := stealthConfig.GetRandomUserAgent()
	log.Printf("[FFUF_ASYNC] Using stealth User-Agent: %s", randomUA)

	// Create temporary file for JSON output
	tmpFile := filepath.Join(os.TempDir(), "ffuf_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile)

	// Update wordlist path
	wordlistPath := "./internal/models/wordlist.txt"
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		wordlistPath = "../internal/models/wordlist.txt"
	}
	log.Printf("[FFUF_ASYNC] Using wordlist: %s", wordlistPath)

	// Count lines for progress estimation
	var wordlistLines int
	if f, err := os.Open(wordlistPath); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			wordlistLines++
		}
		f.Close()
	}
	// Estimate duration: lines / rate (100 req/s)
	// Add 30s buffer for initialization and timeouts
	estimatedSeconds := float64(wordlistLines)/100.0 + 30
	log.Printf("[FFUF_ASYNC] Estimated duration: %.0fs (lines: %d)", estimatedSeconds, wordlistLines)
	startTime := time.Now()

	// Build ffuf command with stealth parameters
	cmd := exec.CommandContext(ctx,
		"ffuf",
		"-u", target+"/FUZZ",
		"-w", wordlistPath,
		"-fc", "404,307,301,302,308",
		"-of", "json",
		"-o", tmpFile,
		"-rate", "100",             // Rate limit: 100 requests per second
		"-p", "0.05-0.1",           // Random delay: 50-100ms between requests
		"-t", "25",                 // Max 25 concurrent threads
		"-timeout", "10",           // Connection timeout: 10 seconds
		"-H", "User-Agent: "+randomUA,
		"-H", "X-Scanner-Origin: ffuf",
		"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"-H", "Accept-Language: en-US,en;q=0.9",
		"-H", "Accept-Encoding: gzip, deflate",
		"-H", "DNT: 1",
		"-H", "Connection: keep-alive",
	)
	
	log.Printf("[FFUF_ASYNC] Stealth mode enabled: rate=100req/s, delay=50-100ms, threads=25")

	// Capture stdout/stderr for progress tracking
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		manager.Fail(taskID, fmt.Errorf("failed to create stdout pipe: %w", err))
		return err
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		manager.Fail(taskID, fmt.Errorf("failed to create stderr pipe: %w", err))
		return err
	}

	// Phase 2: Start scan (5-10%)
	manager.UpdateProgress(taskID, 10, models.StatusRunning)

	// Start command
	if err := cmd.Start(); err != nil {
		log.Printf("[FFUF_ASYNC] Failed to start ffuf: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to start ffuf: %w", err))
		return err
	}

	// Phase 3: Monitor progress (10-95%)
	// FFUF outputs progress info to stderr, we'll parse it
	currentProgress := 10
	stderrLines := make(chan string, 100)
	
	// Read stderr in goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			stderrLines <- scanner.Text()
		}
		close(stderrLines)
	}()

	// Read stdout (if any) but ignore
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			// Just consume stdout
		}
	}()

	// Wait for command to finish with progress updates
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- cmd.Wait()
	}()

	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	scanFinished := false
	var scanErr error
	lineCount := 0

	for !scanFinished {
		select {
		case <-ctx.Done():
			// Context cancelled - kill the process
			log.Printf("[FFUF_ASYNC] Context cancelled for task=%s, killing process", taskID)
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			manager.UpdateProgress(taskID, currentProgress, models.StatusStopped)
			return ctx.Err()

		case err := <-doneChan:
			scanFinished = true
			scanErr = err

		case line, ok := <-stderrLines:
			if !ok {
				stderrLines = nil
				continue
			}
			lineCount++
			log.Printf("[FFUF] %s", line)

		case <-progressTicker.C:
			// Smart progress updates based on estimated duration
			if currentProgress < 90 {
				elapsed := time.Since(startTime).Seconds()
				// Calculate percentage of estimated time elapsed
				// We map 0-100% of time to 10-90% of progress
				timeProgress := (elapsed / estimatedSeconds) * 80.0
				
				targetProgress := 10 + int(timeProgress)
				if targetProgress > 90 {
					targetProgress = 90
				}
				
				// Only update if we are moving forward
				if targetProgress > currentProgress {
					currentProgress = targetProgress
					manager.UpdateProgress(taskID, currentProgress, models.StatusRunning)
				}
			}
		}
	}

	// Check if scan failed
	if scanErr != nil {
		log.Printf("[FFUF_ASYNC] Scan failed: %v", scanErr)
		manager.Fail(taskID, fmt.Errorf("ffuf execution failed: %w", scanErr))
		return scanErr
	}

	// Phase 4: Parse results (90-95%)
	manager.UpdateProgress(taskID, 90, models.StatusRunning)

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("[FFUF_ASYNC] Failed to read output file: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to read ffuf output: %w", err))
		return err
	}

	if len(jsonData) < 10 {
		log.Printf("[FFUF_ASYNC] Output file too small or empty")
		err := fmt.Errorf("ffuf returned empty/invalid output")
		manager.Fail(taskID, err)
		return err
	}

	// Verify it is valid JSON but don't unmarshal into interface{}
	if !json.Valid(jsonData) {
		log.Printf("[FFUF_ASYNC] Invalid JSON output")
		err := fmt.Errorf("ffuf returned invalid json")
		manager.Fail(taskID, err)
		return err
	}

	// Phase 5: Save report (95-100%)
	manager.UpdateProgress(taskID, 95, models.StatusRunning)

	// Complete the task with RawMessage
	manager.Complete(taskID, json.RawMessage(jsonData))
	log.Printf("[FFUF_ASYNC] Scan completed successfully for task=%s", taskID)

	return nil
}

// Legacy ExecuteScan for backward compatibility
func (s *FfufService) ExecuteScan(ctx context.Context, target string) (interface{}, error) {
	log.Printf("[FFUF_SERVICE] Starting scan on target=%s", target)
	
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
		log.Printf("[FFUF_SERVICE] Added https:// prefix, new target=%s", target)
	}

	tmpFile := filepath.Join(os.TempDir(), "ffuf_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile)

	wordlistPath := "./internal/models/wordlist.txt"
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		wordlistPath = "../internal/models/wordlist.txt"
	}
	log.Printf("[FFUF_SERVICE] Using wordlist: %s", wordlistPath)

	cmd := exec.CommandContext(ctx,
		"ffuf",
		"-u", target+"/FUZZ",
		"-w", wordlistPath,
		"-fc", "404,307",
		"-of", "json",
		"-o", tmpFile,
		"-s",
	)

	log.Printf("[FFUF_SERVICE] Executing ffuf command")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[FFUF_SERVICE] FFUF execution failed: %v, output: %s", err, string(output))
		return nil, fmt.Errorf("ffuf execution failed: %v, output: %s", err, string(output))
	}
	log.Printf("[FFUF_SERVICE] FFUF execution completed")

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("[FFUF_SERVICE] Failed to read output file: %v", err)
		return nil, fmt.Errorf("failed to read ffuf output: %w", err)
	}

	if len(jsonData) < 10 {
		log.Printf("[FFUF_SERVICE] Output file too small or empty")
		return nil, fmt.Errorf("ffuf returned empty/invalid output")
	}

	var result interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		log.Printf("[FFUF_SERVICE] Failed to parse JSON output: %v", err)
		return nil, fmt.Errorf("failed to parse ffuf json: %w", err)
	}

	log.Printf("[FFUF_SERVICE] Scan completed successfully")
	return result, nil
}
