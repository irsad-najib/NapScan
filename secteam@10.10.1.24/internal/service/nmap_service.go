package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"

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

func (s *NmapService) ExecuteScan(target string, scanType string, args ...string) (models.NmapRun, error) {
	baseArgs := append([]string{scanType,"-n", "-T4", "-oX", "-"}, args...)
	baseArgs = append(baseArgs, target)

	cmd := exec.Command("nmap", baseArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		log.Printf("Command failed: %v\nArgs: %v\nStderr: %s\nStdout: %s", err, cmd.Args, stderrStr, stdout.String())
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
