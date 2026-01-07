// buatkan untuk nuclei mirip seperti nmap dan ffuf
package routes

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type NucleiRoutes struct {
	client any
}

func (nr *NucleiRoutes) StartScan(c *gin.Context) {
	log.Println("Starting nuclei scan...")

	var req struct {
		Target string `json:"target" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"error":   "Invalid request payload",
			"details": err.Error(),
			"hint":    "Expected JSON body with 'target' field (e.g., {\"target\": \"https://example.com\"})",
		})
		return
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		c.JSON(400, gin.H{
			"error": "target is required",
			"hint":  "Provide a valid URL or hostname (e.g., https://example.com or example.com)",
		})
		return
	}

	// Use timeout to prevent hanging scans
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// Create temporary file for JSONL output (nuclei writes one JSON object per line)
	tmpFile := filepath.Join(os.TempDir(), "nuclei_"+time.Now().Format("20060102150405")+".jsonl")
	defer os.Remove(tmpFile) // cleanup after

	cmd := exec.CommandContext(ctx,
		"nuclei",
		"-target", target,
		"-jsonl",
		"-o", tmpFile,
		"-silent",
		"-nc",
	)

	// Capture stdout and stderr separately for better debugging
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("nuclei scan error for target=%s: %v", target, err)
		c.JSON(500, gin.H{"error": err.Error(), "output": string(output)})
		return
	}

	// Read JSONL output from temporary file
	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("nuclei read output error for target=%s: %v", target, err)
		c.JSON(500, gin.H{"error": "failed to read nuclei output", "details": err.Error()})
		return
	}

	trimmed := strings.TrimSpace(string(jsonData))
	if trimmed == "" {
		c.JSON(200, gin.H{"target": target, "results": []any{}})
		return
	}

	lines := strings.Split(trimmed, "\n")
	results := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			c.JSON(500, gin.H{"error": "failed to parse nuclei jsonl", "details": err.Error(), "line": line})
			return
		}
		results = append(results, obj)
	}

	c.JSON(200, gin.H{"target": target, "results": results})
}
func (nr *NucleiRoutes) SetupRoutes(rg *gin.RouterGroup) {
	nucleiGroup := rg.Group("/nuclei")
	nucleiGroup.POST("/scan", nr.StartScan)
}