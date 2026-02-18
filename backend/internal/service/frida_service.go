package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"napscan-be/pkg/logger"
)

type FridaService struct {
	scriptPath string
}

func NewFridaService() *FridaService {
	// Look for frida_engine/entry.js relative to CWD
	// In production, we might want an env var
	path := os.Getenv("FRIDA_SCRIPT_PATH")
	if path == "" {
		path = "frida_engine/agent.js"
	}
	return &FridaService{
		scriptPath: path,
	}
}

// RunScan executes the Frida script against the target package
func (s *FridaService) RunScan(ctx context.Context, packageName string) (map[string]interface{}, error) {
	// 1. Create a timeout context for the scan duration (e.g., 30-60 seconds)
	scanCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()

	// 2. Prepare Frida Argument list
	// -U: USB device
	// -f: Spawn package
	// -l: Script path
	// -q: Quiet mode (non-interactive)
	args := []string{"-U", "-f", packageName, "-l", s.scriptPath, "-t", "30000"}

	cmd := exec.CommandContext(scanCtx, "frida", args...)

	// CRITICAL: Keep Stdin open to prevent Frida from treating it as EOF and exiting.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	// We do NOT write anything, just hold it open until function return
	defer stdin.Close()

	logger.Debug("[FRIDA] Executing: %s %v", "frida", args)

	// Use io.Pipe to stream output
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start frida: %w", err)
	}

	var outputBuilder strings.Builder
	done := make(chan bool)

	// Stream output in background
	go func() {
		scanner := bufio.NewScanner(pr)

		// IMPORTANT: prevent token too long (Frida JSON bisa panjang)
		buf := make([]byte, 0, 1024*1024)
		scanner.Buffer(buf, 10*1024*1024) // max 10MB per line

		for scanner.Scan() {
			line := scanner.Text()
			logger.Debug("[FRIDA] %s", line)
			outputBuilder.WriteString(line + "\n")
		}

		if err := scanner.Err(); err != nil {
			logger.Error("[FRIDA] Scanner error: %v", err)
		}

		done <- true
	}()

	// Wait for command to finish OR context timeout
	err = cmd.Wait()
	if scanCtx.Err() == context.DeadlineExceeded {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}

	// Close pipe to finish the scanner
	pw.Close()
	<-done

	output := outputBuilder.String()

	// Check exit scenarios
	if scanCtx.Err() == context.DeadlineExceeded {
		logger.Warn("[FRIDA] Scan timed out (expected lifecycle management). Process killed.")
		err = nil
	} else if err != nil {
		// If markers are present, we consider it a partial success (or crash after start)
		if strings.Contains(output, "[[NAPSCAN_JSON_START]]") {
			logger.Warn("[FRIDA] Process finished with error but JSON markers found. proceeding.")
			err = nil
		} else {
			logger.Error("[FRIDA] Execution unexpectedly failed: %v\nOutput: %s", err, output)
			return nil, fmt.Errorf("frida execution failed: %w", err)
		}
	}

	// Parse custom markers - EXTRACT ALL EVENTS
	startMarker := "[[NAPSCAN_JSON_START]]"
	endMarker := "[[NAPSCAN_JSON_END]]"

	var events []map[string]interface{}

	remaining := output

	for {
		startIndex := strings.Index(remaining, startMarker)
		if startIndex == -1 {
			break
		}

		// Move cursor right after START marker
		remaining = remaining[startIndex+len(startMarker):]

		endIndex := strings.Index(remaining, endMarker)
		if endIndex == -1 {
			break
		}

		jsonStr := remaining[:endIndex]

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &event); err != nil {
			logger.Warn("[FRIDA] Warning: Failed to parse event JSON: %v", err)
		} else {
			events = append(events, event)
		}

		// Move cursor right after END marker
		remaining = remaining[endIndex+len(endMarker):]
	}

	if len(events) == 0 {
		logger.Warn("[FRIDA] No valid JSON events found in output.")
		return nil, fmt.Errorf("failed to find valid JSON markers in frida output")
	}

	results := map[string]interface{}{
		"scan_timestamp": time.Now().UTC(),
		"package_name":   packageName,
		"events":         events,
	}

	return results, nil
}

// bundleScript reads a JS file and recursively inlines `load("path/to/file.js")` calls.
func (s *FridaService) bundleScript(path string, visited map[string]bool) (string, error) {
	// Prevent circular dependencies
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if visited[absPath] {
		return "", nil // Already loaded
	}
	visited[absPath] = true

	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}

	scriptContent := string(content)

	// Regex to find load("...")
	// Matches: load("path/to/file.js"); or load('path/to/file.js')
	re := regexp.MustCompile(`load\(['"](.+?)['"]\);?`)

	result := re.ReplaceAllStringFunc(scriptContent, func(match string) string {
		submatch := re.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}
		relPath := submatch[1]

		// Resolve path relative to the current file's directory
		dir := filepath.Dir(path)
		fullPath := filepath.Join(dir, relPath)

		bundled, err := s.bundleScript(fullPath, visited)
		if err != nil {
			logger.Warn("Warning: failed to bundle %s: %v", fullPath, err)
			return fmt.Sprintf("// Error loading %s: %v", relPath, err)
		}

		return fmt.Sprintf("// Begin %s\n%s\n// End %s", relPath, bundled, relPath)
	})

	return result, nil
}
