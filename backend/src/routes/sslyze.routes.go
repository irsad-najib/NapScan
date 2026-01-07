package routes

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

type SslyzeRoutes struct {
	client any
}

func (sr *SslyzeRoutes) StartScan(c *gin.Context) {
	log.Println("Starting sslyze scan...")

	var sslyzeTarget struct {
		Target string `json:"target" binding:"required"`
	}

	if err := c.ShouldBindJSON(&sslyzeTarget); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}


	// Use timeout to prevent hanging scans
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Create temporary file for JSON output
	tmpFile := filepath.Join(os.TempDir(), "sslyze_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile) // cleanup after

	cmd := exec.CommandContext(ctx,
		"sslyze",
		"--json_out", tmpFile,
		 sslyzeTarget.Target,
	)

	// Capture stdout and stderr separately for better debugging
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("sslyze scan error for target=%s: %v", sslyzeTarget.Target, err)
		c.JSON(500, gin.H{"error": err.Error(), "output": string(output)})
		return
	}

	// Read the JSON file
	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("failed to read sslyze output file: %v", err)
		c.JSON(500, gin.H{"error": "failed to read scan results"})
		return
	}

	// Check if output is empty or too small
	// if len(jsonData) < 10 {
	// 	log.Printf("sslyze returned empty/invalid output")
	// 	c.JSON(500, gin.H{"error": "sslyze returned no data", "hint": "check wordlist path or target"})
	// 	return
	// }
	// Return raw JSON with correct content-type
	c.Data(200, "application/json", jsonData)
}

func (sr *SslyzeRoutes) SetupRoutes(r *gin.RouterGroup) {
	r.POST("/sslyze/scan", sr.StartScan)
}