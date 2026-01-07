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

type FfufRoutes struct {
	client any
}

func (fr *FfufRoutes) StartScan(c *gin.Context) {
	log.Println("Starting ffuf scan...")

	var ffufTarget struct {
		Target string `json:"target" binding:"required"`
	}

	if err := c.ShouldBindJSON(&ffufTarget); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	// Ensure URL has protocol
	target := ffufTarget.Target
	if target[:4] != "http" {
		target = "https://" + target
	}

	// Use timeout to prevent hanging scans
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Create temporary file for JSON output
	tmpFile := filepath.Join(os.TempDir(), "ffuf_"+time.Now().Format("20060102150405")+".json")
	defer os.Remove(tmpFile) // cleanup after

	cmd := exec.CommandContext(ctx,
		"ffuf",
		"-u", target+"/FUZZ",
		"-w", "./models/wordlist.txt",
		"-of", "json",
		"-o", tmpFile,
		"-s", // silent mode (no progress bars)
	)

	// Capture stdout and stderr separately for better debugging
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("ffuf scan error for target=%s: %v", target, err)
		c.JSON(500, gin.H{"error": err.Error(), "output": string(output)})
		return
	}

	// Read the JSON file
	jsonData, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("failed to read ffuf output file: %v", err)
		c.JSON(500, gin.H{"error": "failed to read scan results"})
		return
	}

	// Check if output is empty or too small
	if len(jsonData) < 10 {
		log.Printf("ffuf returned empty/invalid output")
		c.JSON(500, gin.H{"error": "ffuf returned no data", "hint": "check wordlist path or target"})
		return
	}
	// Return raw JSON with correct content-type
	c.Data(200, "application/json", jsonData)
}

func (fr *FfufRoutes) SetupRoutes(r *gin.RouterGroup) {
	r.POST("/ffuf/scan", fr.StartScan)
}