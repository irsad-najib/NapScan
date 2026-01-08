package service

import (
	"context"
	"encoding/json"
	"fmt"
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
	// Create temporary file for JSON output
	tmpFile := filepath.Join(os.TempDir(), "sslyze_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile)

	cmd := exec.CommandContext(ctx,
		"sslyze",
		"--json_out", tmpFile,
		target,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sslyze execution failed: %v, output: %s", err, string(output))
	}

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read sslyze output: %w", err)
	}

	var result interface{}
	// SSLyze output might be large, but we parse it to ensure it's valid JSON before sending
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return nil, fmt.Errorf("failed to parse sslyze json: %w", err)
	}

	return result, nil
}
