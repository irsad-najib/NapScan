package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
