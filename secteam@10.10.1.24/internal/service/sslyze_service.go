package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type SslyzeService struct{}

func NewSslyzeService() *SslyzeService {
	return &SslyzeService{}
}

func (s *SslyzeService) ExecuteScan(ctx context.Context, target string) (interface{}, error) {
	log.Printf("[SSLYZE_SERVICE] Starting scan on target=%s", target)
	// Create temporary file for JSON output
	tmpFile := filepath.Join(os.TempDir(), "sslyze_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile)

	cmd := exec.CommandContext(ctx,
		"sslyze",
		"--json_out", tmpFile,
		target,
	)

	log.Printf("[SSLYZE_SERVICE] Executing sslyze command")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[SSLYZE_SERVICE] SSLyze execution failed: %v, output: %s", err, string(output))
		return nil, fmt.Errorf("sslyze execution failed: %v, output: %s", err, string(output))
	}
	log.Printf("[SSLYZE_SERVICE] SSLyze execution completed")

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("[SSLYZE_SERVICE] Failed to read output file: %v", err)
		return nil, fmt.Errorf("failed to read sslyze output: %w", err)
	}

	var result interface{}
	// SSLyze output might be large, but we parse it to ensure it's valid JSON before sending
	if err := json.Unmarshal(jsonData, &result); err != nil {
		log.Printf("[SSLYZE_SERVICE] Failed to parse JSON output: %v", err)
		return nil, fmt.Errorf("failed to parse sslyze json: %w", err)
	}

	log.Printf("[SSLYZE_SERVICE] Scan completed successfully")
	return result, nil
}
