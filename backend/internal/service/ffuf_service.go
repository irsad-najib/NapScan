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

type FfufService struct{}

func NewFfufService() *FfufService {
	return &FfufService{}
}

func (s *FfufService) ExecuteScan(ctx context.Context, target string) (interface{}, error) {
	// Ensure URL has protocol
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	// Create temporary file for JSON output
	tmpFile := filepath.Join(os.TempDir(), "ffuf_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile)

	// Update wordlist path to new location
	wordlistPath := "./internal/models/wordlist.txt"
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		// Fallback for different CWD
		wordlistPath = "../internal/models/wordlist.txt"
	}

	cmd := exec.CommandContext(ctx,
		"ffuf",
		"-u", target+"/FUZZ",
		"-w", wordlistPath,
		"-of", "json",
		"-o", tmpFile,
		"-s", // silent mode
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ffuf execution failed: %v, output: %s", err, string(output))
	}

	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ffuf output: %w", err)
	}

	if len(jsonData) < 10 {
		return nil, fmt.Errorf("ffuf returned empty/invalid output")
	}

	var result interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return nil, fmt.Errorf("failed to parse ffuf json: %w", err)
	}

	return result, nil
}
