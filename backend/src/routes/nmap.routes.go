package routes

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"

	"napscan-be/models"

	"github.com/gin-gonic/gin"
)

type NmapRoutes struct {
	client any
}

type scanResult struct {
	result models.NmapRun
	err    error
}

type CombinedScanResponse struct {
	TCP *models.NmapRun `json:"tcp"`
	UDP *models.NmapRun `json:"udp"`
}

func (nr *NmapRoutes) executeScan(target string, scanType string, args ...string) (models.NmapRun, error) {
	baseArgs := append([]string{scanType,"-n", "-T4", "-oX", "-"}, args...)
	// baseArgs = append([]string{"nmap"}, baseArgs...)
	baseArgs = append(baseArgs, target)

	cmd := exec.Command("nmap", baseArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		log.Printf("Command failed: %v\nArgs: %v\nStderr: %s\nStdout: %s", err, cmd.Args, stderrStr, stdout.String())
		if stderrStr != "" {
			return models.NmapRun{}, fmt.Errorf("%w: %s", err, stderrStr)
		}
		return models.NmapRun{}, err
	}

	var result models.NmapRun
	if err := xml.Unmarshal(stdout.Bytes(), &result); err != nil {
		return models.NmapRun{}, err
	}

	return result, nil
}

func (nr *NmapRoutes) StartFullScan(c *gin.Context) {
	log.Println("Starting parallel Nmap scans (TCP + UDP)...")

	var nmapTarget struct {
		Target string `json:"target" binding:"required"`
	}

	if err := c.ShouldBindJSON(&nmapTarget); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	var wg sync.WaitGroup
	tcpChan := make(chan scanResult, 1)
	udpChan := make(chan scanResult, 1)

	wg.Add(2)

	go func() {
		defer wg.Done()
		result, err := nr.executeScan(nmapTarget.Target, "-sV")
		tcpChan <- scanResult{result: result, err: err}
	}()

	go func() {
		defer wg.Done()
		result, err := nr.executeScan(nmapTarget.Target, "-sU", "-p", "53,67,68,69,123,161,500,1900,4500")
		udpChan <- scanResult{result: result, err: err}
	}()

	wg.Wait()
	close(tcpChan)
	close(udpChan)

	tcpRes := <-tcpChan
	udpRes := <-udpChan

	if tcpRes.err != nil {
		log.Printf("TCP scan error: %v", tcpRes.err)
		c.JSON(500, gin.H{"error": "Failed to execute TCP scan", "details": tcpRes.err.Error()})
		return
	}

	if udpRes.err != nil {
		log.Printf("UDP scan error: %v", udpRes.err)
		c.JSON(500, gin.H{"error": "Failed to execute UDP scan", "details": udpRes.err.Error()})
		return
	}

	response := CombinedScanResponse{
		TCP: &tcpRes.result,
		UDP: &udpRes.result,
	}

	c.JSON(200, response)
}

func (nr *NmapRoutes) SetupRoutes(r *gin.RouterGroup) {
	r.POST("/nmap/scan", nr.StartFullScan)
}