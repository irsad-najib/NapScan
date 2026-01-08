package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type NucleiService struct{}

func NewNucleiService() *NucleiService {
	return &NucleiService{}
}

func (s *NucleiService) ExecuteScan(ctx context.Context, target string) ([]map[string]interface{}, error) {
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

	output, err := cmd.CombinedOutput()
	if err != nil {
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
			return nil, fmt.Errorf("failed to parse nuclei jsonl: %w, line: %s", err, line)
		}
		results = append(results, obj)
	}

	return results, nil
}
