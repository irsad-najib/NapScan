package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"napscan-be/internal/models"
)

type NmapService struct{}

func NewNmapService() *NmapService {
	return &NmapService{}
}

type ScanResult struct {
	Result models.NmapRun
	Err    error
}

type CombinedScanResponse struct {
	TCP     *models.NmapRun `json:"tcp"`
	UDP     *models.NmapRun `json:"udp"`
	BatchID string          `json:"batch_id,omitempty"`
}

// RunNmapAsync is the NEW async scan function following the contract
// func RunX(ctx context.Context, taskID string, manager *ScanManager) error
func RunNmapAsync(ctx context.Context, taskID string, manager *ScanManager) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	log.Printf("[NMAP_ASYNC] Starting async scan for task=%s target=%s", taskID, target)

	// Update to running
	manager.UpdateProgress(taskID, 0, models.StatusRunning)

	// Phase 1: Init (0-10%)
	manager.UpdateProgress(taskID, 5, models.StatusRunning)
	time.Sleep(100 * time.Millisecond) // Small delay to simulate init

	// Build nmap command with context
	args := []string{"-sV", "-n", "-T4", "-oX", "-", target}
	cmd := exec.CommandContext(ctx, "nmap", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Phase 2: Start scan (10%)
	manager.UpdateProgress(taskID, 10, models.StatusRunning)

	// Run command
	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.Run()
	}()

	// Phase 3: Monitor progress (10-90%)
	// We'll simulate progress based on time since we can't parse stdout in real-time easily
	progressTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()

	currentProgress := 10
	progressIncrement := 10

	scanFinished := false
	var scanErr error

	for !scanFinished {
		select {
		case <-ctx.Done():
			// Context cancelled - kill the process
			log.Printf("[NMAP_ASYNC] Context cancelled for task=%s, killing process", taskID)
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			manager.UpdateProgress(taskID, currentProgress, models.StatusStopped)
			return ctx.Err()

		case err := <-errChan:
			scanFinished = true
			scanErr = err

		case <-progressTicker.C:
			// Increment progress up to 90%
			if currentProgress < 90 {
				currentProgress += progressIncrement
				if currentProgress > 90 {
					currentProgress = 90
				}
				manager.UpdateProgress(taskID, currentProgress, models.StatusRunning)
				log.Printf("[NMAP_ASYNC] Progress update: %d%%", currentProgress)
			}
		}
	}

	// Check if scan failed
	if scanErr != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		log.Printf("[NMAP_ASYNC] Scan failed: %v, stderr: %s", scanErr, stderrStr)
		
		finalErr := scanErr
		if stderrStr != "" {
			finalErr = fmt.Errorf("%w: %s", scanErr, stderrStr)
		}
		
		manager.Fail(taskID, finalErr)
		return finalErr
	}

	// Phase 4: Parse results (90-95%)
	manager.UpdateProgress(taskID, 90, models.StatusRunning)

	var result models.NmapRun
	if err := xml.Unmarshal(stdout.Bytes(), &result); err != nil {
		log.Printf("[NMAP_ASYNC] Failed to parse XML: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to parse nmap output: %w", err))
		return err
	}

	// Phase 5: Save report (95-100%)
	manager.UpdateProgress(taskID, 95, models.StatusRunning)

	// Convert result to map[string]interface{} for storage
	resultMap := map[string]interface{}{
		"hosts": result.Hosts,
	}

	// Complete the task
	manager.Complete(taskID, resultMap)
	log.Printf("[NMAP_ASYNC] Scan completed successfully for task=%s", taskID)

	return nil
}

// RunNmapParallelAsync runs TCP and UDP scans in parallel (async version)
func RunNmapParallelAsync(ctx context.Context, taskID string, manager *ScanManager) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	log.Printf("[NMAP_PARALLEL] Starting parallel scan for task=%s target=%s", taskID, target)

	manager.UpdateProgress(taskID, 0, models.StatusRunning)

	var wg sync.WaitGroup
	tcpChan := make(chan ScanResult, 1)
	udpChan := make(chan ScanResult, 1)

	wg.Add(2)

	// TCP Scan
	go func() {
		defer wg.Done()
		log.Printf("[NMAP_PARALLEL] Starting TCP scan")
		
		args := []string{"-sV", "-n", "-T4", "-oX", "-", target}
		result, err := executeSingleNmapScan(ctx, args)
		
		tcpChan <- ScanResult{Result: result, Err: err}
		
		if err != nil {
			log.Printf("[NMAP_PARALLEL] TCP scan failed: %v", err)
		} else {
			log.Printf("[NMAP_PARALLEL] TCP scan completed")
		}
	}()

	// UDP Scan
	go func() {
		defer wg.Done()
		log.Printf("[NMAP_PARALLEL] Starting UDP scan")
		
		args := []string{"-sU", "-n", "-T4", "-p", "53,67,68,69,123,161,500,1900,4500", "-oX", "-", target}
		result, err := executeSingleNmapScan(ctx, args)
		
		udpChan <- ScanResult{Result: result, Err: err}
		
		if err != nil {
			log.Printf("[NMAP_PARALLEL] UDP scan failed: %v", err)
		} else {
			log.Printf("[NMAP_PARALLEL] UDP scan completed")
		}
	}()

	// Progress monitoring
	progressTicker := time.NewTicker(3 * time.Second)
	defer progressTicker.Stop()
	
	currentProgress := 10
	scansDone := 0
	
	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	// Monitor progress
	for scansDone < 2 {
		select {
		case <-ctx.Done():
			log.Printf("[NMAP_PARALLEL] Context cancelled, stopping scans")
			manager.UpdateProgress(taskID, currentProgress, models.StatusStopped)
			return ctx.Err()
			
		case <-doneChan:
			scansDone = 2
			
		case <-progressTicker.C:
			if currentProgress < 85 {
				currentProgress += 15
				manager.UpdateProgress(taskID, currentProgress, models.StatusRunning)
			}
		}
	}

	close(tcpChan)
	close(udpChan)

	tcpRes := <-tcpChan
	udpRes := <-udpChan

	// Check for errors
	if tcpRes.Err != nil {
		manager.Fail(taskID, fmt.Errorf("TCP scan error: %w", tcpRes.Err))
		return tcpRes.Err
	}
	if udpRes.Err != nil {
		manager.Fail(taskID, fmt.Errorf("UDP scan error: %w", udpRes.Err))
		return udpRes.Err
	}

	manager.UpdateProgress(taskID, 90, models.StatusRunning)

	// Combine results
	combinedResult := map[string]interface{}{
		"tcp": tcpRes.Result,
		"udp": udpRes.Result,
	}

	manager.Complete(taskID, combinedResult)
	log.Printf("[NMAP_PARALLEL] Parallel scan completed successfully for task=%s", taskID)

	return nil
}

// executeSingleNmapScan is a helper to execute a single nmap command
func executeSingleNmapScan(ctx context.Context, args []string) (models.NmapRun, error) {
	cmd := exec.CommandContext(ctx, "nmap", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		if stderrStr != "" {
			return models.NmapRun{}, fmt.Errorf("%w: %s", err, stderrStr)
		}
		return models.NmapRun{}, err
	}

	var result models.NmapRun
	if err := xml.Unmarshal(stdout.Bytes(), &result); err != nil {
		return models.NmapRun{}, err
	}

	return result, nil
}

// Legacy methods for backward compatibility
func (s *NmapService) ExecuteScan(target string, scanType string, args ...string) (models.NmapRun, error) {
	baseArgs := append([]string{scanType, "-n", "-T4", "-oX", "-"}, args...)
	baseArgs = append(baseArgs, target)
	return executeSingleNmapScan(context.Background(), baseArgs)
}

func (s *NmapService) RunParallelScan(target string) (*CombinedScanResponse, error) {
	log.Printf("[NMAP_SERVICE] Starting parallel scan on target=%s", target)
	var wg sync.WaitGroup
	tcpChan := make(chan ScanResult, 1)
	udpChan := make(chan ScanResult, 1)

	wg.Add(2)

	go func() {
		defer wg.Done()
		log.Printf("[NMAP_SERVICE] Starting TCP scan")
		result, err := s.ExecuteScan(target, "-sV")
		if err != nil {
			log.Printf("[NMAP_SERVICE] TCP scan failed: %v", err)
		} else {
			log.Printf("[NMAP_SERVICE] TCP scan completed")
		}
		tcpChan <- ScanResult{Result: result, Err: err}
	}()

	go func() {
		defer wg.Done()
		log.Printf("[NMAP_SERVICE] Starting UDP scan")
		result, err := s.ExecuteScan(target, "-sU", "-p", "53,67,68,69,123,161,500,1900,4500")
		if err != nil {
			log.Printf("[NMAP_SERVICE] UDP scan failed: %v", err)
		} else {
			log.Printf("[NMAP_SERVICE] UDP scan completed")
		}
		udpChan <- ScanResult{Result: result, Err: err}
	}()

	wg.Wait()
	close(tcpChan)
	close(udpChan)

	tcpRes := <-tcpChan
	udpRes := <-udpChan

	if tcpRes.Err != nil {
		log.Printf("[NMAP_SERVICE] Parallel scan failed - TCP error: %v", tcpRes.Err)
		return nil, fmt.Errorf("TCP scan error: %w", tcpRes.Err)
	}

	if udpRes.Err != nil {
		log.Printf("[NMAP_SERVICE] Parallel scan failed - UDP error: %v", udpRes.Err)
		return nil, fmt.Errorf("UDP scan error: %w", udpRes.Err)
	}

	log.Printf("[NMAP_SERVICE] Parallel scan completed successfully")
	return &CombinedScanResponse{
		TCP: &tcpRes.Result,
		UDP: &udpRes.Result,
	}, nil
}
