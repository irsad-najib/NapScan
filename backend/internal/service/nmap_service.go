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
	TCP *models.NmapRun `json:"tcp"`
	UDP *models.NmapRun `json:"udp"`
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
	var wg sync.WaitGroup
	tcpChan := make(chan ScanResult, 1)
	udpChan := make(chan ScanResult, 1)

	wg.Add(2)

	go func() {
		defer wg.Done()
		result, err := s.ExecuteScan(target, "-sV")
		tcpChan <- ScanResult{Result: result, Err: err}
	}()

	go func() {
		defer wg.Done()
		result, err := s.ExecuteScan(target, "-sU", "-p", "53,67,68,69,123,161,500,1900,4500")
		udpChan <- ScanResult{Result: result, Err: err}
	}()

	wg.Wait()
	close(tcpChan)
	close(udpChan)

	tcpRes := <-tcpChan
	udpRes := <-udpChan

	if tcpRes.Err != nil {
		return nil, fmt.Errorf("TCP scan error: %w", tcpRes.Err)
	}

	if udpRes.Err != nil {
		return nil, fmt.Errorf("UDP scan error: %w", udpRes.Err)
	}

	return &CombinedScanResponse{
		TCP: &tcpRes.Result,
		UDP: &udpRes.Result,
	}, nil
}
