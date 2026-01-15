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

type FfufService struct{}

func NewFfufService() *FfufService {
	return &FfufService{}
}

func (s *FfufService) ExecuteScan(ctx context.Context, target string) (interface{}, error) {
	log.Printf("[FFUF_SERVICE] Starting scan on target=%s", target)
	// Ensure URL has protocol
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
		log.Printf("[FFUF_SERVICE] Added https:// prefix, new target=%s", target)
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
	log.Printf("[FFUF_SERVICE] Using wordlist: %s", wordlistPath)

	cmd := exec.CommandContext(ctx,
		"ffuf",
		"-u", target+"/FUZZ",
		"-w", wordlistPath,
		"-fc", "404,307",
		"-of", "json",
		"-o", tmpFile,
		"-s", // silent mode
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
