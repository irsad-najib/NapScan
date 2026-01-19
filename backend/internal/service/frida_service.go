package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type FridaService struct {
	scriptPath string
}

func NewFridaService() *FridaService {
	// Look for frida_engine/entry.js relative to CWD
	// In production, we might want an env var
	path := os.Getenv("FRIDA_SCRIPT_PATH")
	if path == "" {
		path = "frida_engine/entry.js"
	}
	return &FridaService{
		scriptPath: path,
	}
}

// RunScan executes the Frida script against the target package
// It assumes a device is connected (-U) and ready.
func (s *FridaService) RunScan(ctx context.Context, packageName string) (map[string]interface{}, error) {
	// frida -U -f <package> -l <script> --no-pause
	// We use -U for USB device (or emulator).
	// --no-pause to let app start immediately.
	// We might need -q (quiet) to reduce noise, but our script handles markers.
	
	cmd := exec.CommandContext(ctx, "frida", "-U", "-f", packageName, "-l", s.scriptPath)
	// Should we add a timeout via context? Caller handles context.

	log.Printf("[FRIDA] Executing: %s", cmd.String())
	
	// Capture combined output
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)
	
	if err != nil {
		// Frida might exit with error if app crashes or device not found
		log.Printf("[FRIDA] Execution failed: %v\nOutput: %s", err, output)
		return nil, fmt.Errorf("frida execution failed: %w", err)
	}

	// Parse custom markers
	startMarker := "[[NAPSCAN_JSON_START]]"
	endMarker := "[[NAPSCAN_JSON_END]]"
	
	startIndex := strings.Index(output, startMarker)
	endIndex := strings.Index(output, endMarker)
	
	if startIndex == -1 || endIndex == -1 || startIndex >= endIndex {
		log.Printf("[FRIDA] Markers not found in output:\n%s", output)
		return nil, fmt.Errorf("failed to find valid JSON markers in frida output")
	}
	
	jsonStr := output[startIndex+len(startMarker) : endIndex]
	var results map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &results); err != nil {
		return nil, fmt.Errorf("failed to parse frida json: %w", err)
	}
	
	// Add metadata
	results["scan_timestamp"] = time.Now().UTC()
	results["package_name"] = packageName
	
	return results, nil
}
