package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"napscan-be/pkg/logger"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"napscan-be/internal/models"
)

type SslyzeService struct{}

func NewSslyzeService() *SslyzeService {
	return &SslyzeService{}
}

// RunSslyzeAsync is the async scan function following the contract
func RunSslyzeAsync(ctx context.Context, taskID string, manager *ScanManager) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	logger.Info("[SSLYZE_ASYNC] Starting async scan for task=%s target=%s", taskID, target)

	// Update to running
	manager.UpdateProgress(taskID, 0, models.StatusRunning)

	// Create temporary file for JSON output
	tmpFile := filepath.Join(os.TempDir(), "sslyze_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile)

	// Sanitize target
	cleanTarget := target
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			cleanTarget = u.Hostname()
		}
	}

	// Build sslyze command with context
	cmd := exec.CommandContext(ctx,
		"sslyze",
		"--json_out", tmpFile,
		cleanTarget,
	)

	// Phase 1: Start scan (0-50%)
	manager.UpdateProgress(taskID, 10, models.StatusRunning)

	logger.Info("[SSLYZE_ASYNC] Executing sslyze command")

	// Run command in background
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.Run()
	}()

	// Phase 2: Running (50%)
	manager.UpdateProgress(taskID, 50, models.StatusRunning)

	// Wait for completion or cancellation
	select {
	case <-ctx.Done():
		// Context cancelled - kill the process
		logger.Warn("[SSLYZE_ASYNC] Context cancelled for task=%s, killing process", taskID)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		manager.UpdateProgress(taskID, 50, models.StatusStopped)
		return ctx.Err()

	case err := <-errChan:
		// Check if file exists and has content regardless of exit code
		if fileInfo, statErr := os.Stat(tmpFile); statErr == nil && fileInfo.Size() > 0 {
			logger.Warn("[SSLYZE_ASYNC] Process finished with error %v but output file exists. Proceeding...", err)
		} else if err != nil {
			logger.Error("[SSLYZE_ASYNC] SSLyze execution failed: %v", err)
			logger.Error("[SSLYZE_ASYNC] Command Output: %s", outputBuffer.String())
			manager.Fail(taskID, fmt.Errorf("sslyze execution failed: %w, output: %s", err, outputBuffer.String()))
			return err
		}
	}

	// Phase 3: Parse results (90%)
	manager.UpdateProgress(taskID, 90, models.StatusRunning)

	// Check file size / existence before reading
	if info, err := os.Stat(tmpFile); err != nil || info.Size() == 0 {
		logger.Error("[SSLYZE_ASYNC] Output file empty or missing. stderr: %s", outputBuffer.String())
		manager.Fail(taskID, fmt.Errorf("sslyze produced no output. stderr: %s", outputBuffer.String()))
		return fmt.Errorf("sslyze produced no output")
	}

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		logger.Error("[SSLYZE_ASYNC] Failed to read output file: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to read sslyze output: %w", err))
		return err
	}

	var result interface{}
	decoder := json.NewDecoder(bytes.NewReader(jsonData))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		logger.Error("[SSLYZE_ASYNC] Failed to parse JSON output: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to parse sslyze json: %w", err))
		return err
	}

	// Sanitize result to strings for huge numbers
	sanitizeResult(result)

	// Phase 4: Complete (100%)
	manager.Complete(taskID, result)
	logger.Info("[SSLYZE_ASYNC] Scan completed successfully for task=%s", taskID)

	return nil
}

// sanitizeResult recursively converts json.Number to string to prevent overflow
func sanitizeResult(v interface{}) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, v2 := range val {
			if num, ok := v2.(json.Number); ok {
				val[k] = num.String()
			} else {
				sanitizeResult(v2)
			}
		}
	case []interface{}:
		for i, v2 := range val {
			if num, ok := v2.(json.Number); ok {
				val[i] = num.String()
			} else {
				sanitizeResult(v2)
			}
		}
	}
}

// Legacy ExecuteScan for backward compatibility
func (s *SslyzeService) ExecuteScan(ctx context.Context, target string) (interface{}, error) {
	logger.Info("[SSLYZE_SERVICE] Starting scan on target=%s", target)
	tmpFile := filepath.Join(os.TempDir(), "sslyze_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile)

	// Sanitize target
	cleanTarget := target
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			cleanTarget = u.Hostname()
		}
	}

	cmd := exec.CommandContext(ctx,
		"sslyze",
		"--json_out", tmpFile,
		cleanTarget,
	)

	logger.Info("[SSLYZE_SERVICE] Executing sslyze command")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("[SSLYZE_SERVICE] SSLyze execution failed: %v, output: %s", err, string(output))
		return nil, fmt.Errorf("sslyze execution failed: %v, output: %s", err, string(output))
	}
	logger.Info("[SSLYZE_SERVICE] SSLyze execution completed")

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		logger.Error("[SSLYZE_SERVICE] Failed to read output file: %v", err)
		return nil, fmt.Errorf("failed to read sslyze output: %w", err)
	}

	var result interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		logger.Error("[SSLYZE_SERVICE] Failed to parse JSON output: %v", err)
		return nil, fmt.Errorf("failed to parse sslyze json: %w", err)
	}

	logger.Info("[SSLYZE_SERVICE] Scan completed successfully")
	return result, nil
}
