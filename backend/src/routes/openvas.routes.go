package routes

import (
	"context"
	"encoding/xml"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type OpenVasRoutes struct {
	// Kamu bisa isi dengan db atau config lainnya nanti
}

func openvasGMPUsername() string {
	if v := strings.TrimSpace(os.Getenv("OPENVAS_GMP_USERNAME")); v != "" {
		return v
	}
	return "admin"
}

func openvasGMPPassword() string {
	if v := strings.TrimSpace(os.Getenv("OPENVAS_GMP_PASSWORD")); v != "" {
		return v
	}
	return "admin"
}

func resolveComposePath() (string, error) {
	// Allow override via env (useful for different deployments)
	for _, key := range []string{"OPENVAS_COMPOSE_PATH", "NAPSCAN_COMPOSE_PATH"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			abs, err := filepath.Abs(v)
			if err != nil {
				return "", err
			}
			if _, err := os.Stat(abs); err != nil {
				return "", err
			}
			return abs, nil
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Walk up a few levels to find docker-compose.yml (repo root)
	dir := wd
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "docker-compose.yml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", errors.New("docker-compose.yml not found; set OPENVAS_COMPOSE_PATH or NAPSCAN_COMPOSE_PATH")
}

func openvasGVMDSocketPath() string {
	if v := strings.TrimSpace(os.Getenv("OPENVAS_GVMD_SOCKET")); v != "" {
		return v
	}
	return "/run/gvmd/gvmd.sock"
}

func openvasRunGVMCLI(ctx context.Context, xmlCommand string) ([]byte, error) {
	// Preferred path: call gvm-cli directly (works in container without docker)
	if gvmcli, err := exec.LookPath("gvm-cli"); err == nil {
		args := []string{
			"--gmp-username", openvasGMPUsername(),
			"--gmp-password", openvasGMPPassword(),
			"socket",
			"--socketpath", openvasGVMDSocketPath(),
			"--xml", xmlCommand,
		}

		// gvm-tools refuses to run as root; when our API runs as root (for nmap),
		// drop privileges for this subprocess.
		if os.Geteuid() == 0 {
			runAs := strings.TrimSpace(os.Getenv("OPENVAS_RUN_AS_USER"))
			if runAs == "" {
				runAs = "napscan"
			}
			if runuserPath, err := exec.LookPath("runuser"); err == nil {
				cmd := exec.CommandContext(ctx, runuserPath, append([]string{"-u", runAs, "--", gvmcli}, args...)...)
				return cmd.CombinedOutput()
			}
		}

		cmd := exec.CommandContext(ctx, gvmcli, args...)
		return cmd.CombinedOutput()
	}

	// Fallback: use docker compose + gvm-tools (useful for local dev outside containers)
	composePath, err := resolveComposePath()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx,
		"docker", "compose", "-f", composePath,
		"run", "--rm", "gvm-tools",
		"gvm-cli",
		"--gmp-username", openvasGMPUsername(),
		"--gmp-password", openvasGMPPassword(),
		"socket",
		"--xml", xmlCommand,
	)
	return cmd.CombinedOutput()
}

func (ov *OpenVasRoutes) GetVersion(c *gin.Context) {
	log.Println("Checking OpenVAS connectivity...")

	// Tanpa timeout: beberapa perintah GVM bisa lama
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	output, err := openvasRunGVMCLI(ctx, "<get_version/>")
	if err != nil {
		log.Printf("OpenVAS error: %v", err)
		c.JSON(500, gin.H{
			"error":  "Failed to communicate with OpenVAS",
			"details": err.Error(),
			"log":     string(output),
		})
		return
	}

	// Karena OpenVAS membalas dalam XML, kita kirim raw XML-nya
	// Di frontend nanti kamu bisa parse XML ini
	c.Data(200, "application/xml", output)
}

func (ov *OpenVasRoutes) StartScan(c *gin.Context) {
	log.Println("=== StartScan called ===")
	
	var request struct {
		Target string `json:"target" binding:"required"`
		Name   string `json:"name"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("ERROR: Failed to bind JSON: %v", err)
		c.JSON(400, gin.H{"error": "Target IP/Host is required"})
		return
	}

	log.Printf("DEBUG: Request received - Target: %s, Name: %s", request.Target, request.Name)

	// Set default name jika tidak diberikan
	targetName := request.Name
	if targetName == "" {
		targetName = "Scan-" + request.Target + "-" + time.Now().Format("20060102-150405")
	}
	log.Printf("DEBUG: Using scan name: %s", targetName)

	// Tanpa timeout: scan OpenVAS bisa lama
	ctx := context.Background()

	log.Printf("DEBUG: Using gvm-cli socketpath: %s", openvasGVMDSocketPath())

	// Step 1: Create Target
	log.Printf("STEP 1: Creating OpenVAS target for %s", request.Target)
	// Port List ID untuk "All IANA assigned TCP" (default OpenVAS port list)
	portListID := "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
	createTargetXML := `<create_target>
		<name>` + targetName + `</name>
		<hosts>` + request.Target + `</hosts>
		<port_list id="` + portListID + `"/>
	</create_target>`
	
	log.Printf("DEBUG: Create target XML command: %s", createTargetXML)

	log.Println("DEBUG: Executing gvm-cli for create target...")
	output, err := openvasRunGVMCLI(ctx, createTargetXML)
	log.Printf("DEBUG: Command output length: %d bytes", len(output))
	
	if err != nil {
		log.Printf("ERROR: Failed to create target: %v", err)
		log.Printf("ERROR: Command output: %s", string(output))
		c.JSON(500, gin.H{
			"error":   "Failed to create OpenVAS target",
			"details": err.Error(),
			"log":     string(output),
		})
		return
	}

	// Parse target ID dari response XML
	targetID := extractIDFromXML(string(output))
	if targetID == "" {
		c.JSON(500, gin.H{
			"error": "Failed to extract target ID",
			"log":   string(output),
		})
		return
	}

	log.Printf("Target created with ID: %s", targetID)

	// Step 2: Create Task dengan scan config (Full and fast)
	// Config ID untuk "Full and fast": daba56c8-73ec-11df-a475-002264764cea
	createTaskXML := `<create_task>
		<name>` + targetName + `</name>
		<target id="` + targetID + `"/>
		<config id="daba56c8-73ec-11df-a475-002264764cea"/>
		<scanner id="08b69003-5fc2-4037-a479-93b440211c73"/>
	</create_task>`

	output, err = openvasRunGVMCLI(ctx, createTaskXML)
	if err != nil {
		log.Printf("Failed to create task: %v", err)
		c.JSON(500, gin.H{
			"error":   "Failed to create OpenVAS task",
			"details": err.Error(),
			"log":     string(output),
		})
		return
	}

	taskID := extractIDFromXML(string(output))
	if taskID == "" {
		c.JSON(500, gin.H{
			"error": "Failed to extract task ID",
			"log":   string(output),
		})
		return
	}

	log.Printf("Task created with ID: %s", taskID)
   
	// Step 3: Start Task
	startTaskXML := `<start_task task_id="` + taskID + `"/>`

	output, err = openvasRunGVMCLI(ctx, startTaskXML)
	if err != nil {
		log.Printf("Failed to start task: %v", err)
		c.JSON(500, gin.H{
			"error":   "Failed to start OpenVAS scan",
			"details": err.Error(),
			"log":     string(output),
		})
		return
	}

	log.Printf("SUCCESS: Scan started successfully for task %s", taskID)
	log.Printf("DEBUG: Final response - targetID: %s, taskID: %s", targetID, taskID)
	log.Println("=== StartScan completed successfully ===")

	// Optional: tunggu sampai selesai biar FE langsung dapat status completed
	// Pakai query param: /openvas/scan?wait=true (atau wait=1)
	waitParam := strings.ToLower(strings.TrimSpace(c.DefaultQuery("wait", "0")))
	shouldWait := waitParam == "1" || waitParam == "true" || waitParam == "yes"
	if !shouldWait {
		c.JSON(200, gin.H{
			"message":  "OpenVAS scan started successfully",
			"target":   request.Target,
			"targetID": targetID,
			"taskID":   taskID,
			"scanName": targetName,
			"status":   "running",
			"progress": 0,
		})
		return
	}

	log.Printf("DEBUG: wait=true; polling task status until completion for task %s", taskID)
	pollInterval := 10 * time.Second
	lastProgress := -1
	lastStatus := ""
	for {
		getTaskXML := `<get_tasks task_id="` + taskID + `" details="1"/>`
		out, err := openvasRunGVMCLI(ctx, getTaskXML)
		if err != nil {
			log.Printf("ERROR: Failed to poll task status: %v", err)
			c.JSON(500, gin.H{
				"error":   "Failed to poll task status",
				"details": err.Error(),
				"log":     string(out),
				"taskID":  taskID,
			})
			return
		}

		xmlStr := extractCleanXML(string(out))
		status := extractXMLTag(xmlStr, "status")
		progressStr := extractXMLTag(xmlStr, "progress")
		reportID := extractXMLAttribute(xmlStr, "report", "id")
		progressInt, _ := strconv.Atoi(progressStr)

		// Map status ke bentuk yang konsisten dengan endpoint status
		statusText := strings.ToLower(strings.TrimSpace(status))
		switch status {
		case "Running":
			statusText = "running"
		case "Done":
			statusText = "completed"
		case "Stopped":
			statusText = "stopped"
		case "Requested":
			statusText = "queued"
		}

		if progressInt != lastProgress || statusText != lastStatus {
			log.Printf("DEBUG: Task %s status=%s progress=%d reportID=%s", taskID, statusText, progressInt, reportID)
			lastProgress = progressInt
			lastStatus = statusText
		}

		if statusText == "completed" {
			c.JSON(200, gin.H{
				"message":  "OpenVAS scan completed",
				"target":   request.Target,
				"targetID": targetID,
				"taskID":   taskID,
				"scanName": targetName,
				"status":   "completed",
				"progress": progressInt,
				"reportID": reportID,
			})
			return
		}

		time.Sleep(pollInterval)
	}
}

// GetTaskStatus - endpoint untuk cek progress scan
func (ov *OpenVasRoutes) GetTaskStatus(c *gin.Context) {
	taskID := c.Param("taskId")
	log.Printf("=== GetTaskStatus called for task: %s ===", taskID)

	if taskID == "" {
		c.JSON(400, gin.H{"error": "Task ID is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get task details dengan <get_tasks task_id="..."/>
	getTaskXML := `<get_tasks task_id="` + taskID + `" details="1"/>`
	log.Printf("DEBUG: Get task XML command: %s", getTaskXML)

	log.Println("DEBUG: Executing gvm-cli for get task...")
	output, err := openvasRunGVMCLI(ctx, getTaskXML)
	log.Printf("DEBUG: Command output length: %d bytes", len(output))

	if err != nil {
		log.Printf("ERROR: Failed to get task status: %v", err)
		log.Printf("ERROR: Command output: %s", string(output))
		c.JSON(500, gin.H{
			"error":   "Failed to get task status",
			"details": err.Error(),
			"log":     string(output),
		})
		return
	}

	// Clean docker compose output and parse XML response
	xmlStr := extractCleanXML(string(output))
	log.Printf("DEBUG: XML Response snippet: %s", truncateString(xmlStr, 500))

	status := extractXMLTag(xmlStr, "status")
	progress := extractXMLTag(xmlStr, "progress")
	reportID := extractXMLAttribute(xmlStr, "report", "id")

	log.Printf("DEBUG: Parsed - Status: %s, Progress: %s, ReportID: %s", status, progress, reportID)

	// Convert progress ke integer
	progressInt, _ := strconv.Atoi(progress)

	// Tentukan status dalam bahasa yang mudah dipahami
	var statusText string
	switch status {
	case "Running":
		statusText = "running"
	case "Done":
		statusText = "completed"
	case "Stopped":
		statusText = "stopped"
	case "Requested":
		statusText = "queued"
	default:
		statusText = strings.ToLower(status)
	}

	log.Printf("SUCCESS: Task status retrieved - %s (%d%%)", statusText, progressInt)
	log.Println("=== GetTaskStatus completed ===")

	c.JSON(200, gin.H{
		"taskID":   taskID,
		"status":   statusText,
		"progress": progressInt,
		"reportID": reportID,
		"rawXML":   xmlStr,
	})
}

// GetScanReport - endpoint untuk ambil hasil scan
func (ov *OpenVasRoutes) GetScanReport(c *gin.Context) {
	reportID := c.Param("reportId")
	log.Printf("=== GetScanReport called for report: %s ===", reportID)

	if reportID == "" {
		c.JSON(400, gin.H{"error": "Report ID is required"})
		return
	}

	// Optional format parameter (default: xml, bisa juga json/pdf/html)
	format := c.DefaultQuery("format", "xml")
	log.Printf("DEBUG: Report format requested: %s", format)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Get report dengan format tertentu
	getReportXML := `<get_reports report_id="` + reportID + `" details="1"/>`
	log.Printf("DEBUG: Get report XML command: %s", getReportXML)

	log.Println("DEBUG: Executing gvm-cli for get report...")
	output, err := openvasRunGVMCLI(ctx, getReportXML)
	log.Printf("DEBUG: Command output length: %d bytes", len(output))

	if err != nil {
		log.Printf("ERROR: Failed to get report: %v", err)
		log.Printf("ERROR: Command output: %s", string(output))
		c.JSON(500, gin.H{
			"error":   "Failed to get scan report",
			"details": err.Error(),
			"log":     string(output),
		})
		return
	}

	// Clean docker compose output before parsing
	xmlStr := extractCleanXML(string(output))
	log.Printf("DEBUG: Clean XML Response snippet: %s", truncateString(xmlStr, 500))

	// Parse XML ke struktur JSON
	reportData, err := parseReportXML(xmlStr)
	if err != nil {
		log.Printf("ERROR: Failed to parse XML report: %v", err)
		// Fallback: return raw XML if parsing fails
		c.JSON(200, gin.H{
			"reportID": reportID,
			"format":   "xml-fallback",
			"rawXML":   xmlStr,
			"error":    "Failed to parse XML, returning raw format",
		})
		return
	}

	log.Printf("DEBUG: Report summary - Hosts: %d, Total Vulns: %d, High: %d, Medium: %d, Low: %d",
		len(reportData.Hosts), reportData.Summary.TotalVulns, reportData.Summary.HighVulns, 
		reportData.Summary.MediumVulns, reportData.Summary.LowVulns)

	log.Printf("SUCCESS: Report retrieved and parsed successfully")
	log.Println("=== GetScanReport completed ===")

	// Return comprehensive JSON format
	c.JSON(200, reportData)
}

// Struktur untuk parsing XML report
type XMLReport struct {
	XMLName xml.Name `xml:"get_reports_response"`
	Report  struct {
		ID             string `xml:"id,attr"`
		FormatID       string `xml:"format_id"`
		ContentType    string `xml:"content_type"`
		Type           string `xml:"type"`
		CreationTime   string `xml:"creation_time"`
		ModificationTime string `xml:"modification_time"`
		ScanRunStatus  string `xml:"scan_run_status"`
		
		Task struct {
			ID      string `xml:"id,attr"`
			Name    string `xml:"name"`
			Comment string `xml:"comment"`
			Target  struct {
				ID   string `xml:"id,attr"`
				Name string `xml:"name"`
			} `xml:"target"`
		} `xml:"task"`
		
		ScanConfig struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
			Type string `xml:"type"`
		} `xml:"scan_config"`
		
		Scanner struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
			Type string `xml:"type"`
		} `xml:"scanner"`
		
		ReportFormat struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"report_format"`
		
		Timestamp     string `xml:"timestamp"`
		Timezone      string `xml:"timezone"`
		TimezoneAbbrev string `xml:"timezone_abbrev"`
		
		Ports struct {
			Count int `xml:"count"`
			Ports []struct {
				Text     string `xml:",chardata"`
				Host     string `xml:"host"`
				Protocol string `xml:"protocol"`
			} `xml:"port"`
		} `xml:"ports"`
		
		Results struct {
			Start int `xml:"start,attr"`
			Max   int `xml:"max,attr"`
			Count int `xml:",chardata"`
			Results []struct {
				ID   string `xml:"id,attr"`
				Name string `xml:"name"`
				Host struct {
					Text     string `xml:",chardata"`
					Hostname string `xml:"hostname"`
					Asset    struct {
						ID string `xml:"asset_id,attr"`
					} `xml:"asset"`
				} `xml:"host"`
				Port     string `xml:"port"`
				NVT      struct {
					OID      string `xml:"oid,attr"`
					Name     string `xml:"name"`
					Family   string `xml:"family"`
					CVSSBase string `xml:"cvss_base"`
					Severity string `xml:"severity"`
					Tags     string `xml:"tags"`
					Type     string `xml:"type"`
					Refs     struct {
						Ref []struct {
							Type string `xml:"type,attr"`
							ID   string `xml:"id,attr"`
						} `xml:"ref"`
					} `xml:"refs"`
					Cert struct {
						CertRef []struct {
							Type string `xml:"type,attr"`
							ID   string `xml:"id,attr"`
						} `xml:"cert_ref"`
					} `xml:"cert"`
					Solution struct {
						Type string `xml:"type,attr"`
						Text string `xml:",chardata"`
					} `xml:"solution"`
					Xrefs struct {
						Xref []struct {
							Type string `xml:"type,attr"`
							ID   string `xml:"id,attr"`
						} `xml:"xref"`
					} `xml:"xrefs"`
				} `xml:"nvt"`
				Threat      string `xml:"threat"`
				Severity    string `xml:"severity"`
				QoD         struct {
					Value int    `xml:"value"`
					Type  string `xml:"type"`
				} `xml:"qod"`
				Description string `xml:"description"`
				Original    struct {
					Threat   string `xml:"threat"`
					Severity string `xml:"severity"`
				} `xml:"original_threat,omitempty"`
				CreationTime     string `xml:"creation_time"`
				ModificationTime string `xml:"modification_time"`
			} `xml:"result"`
		} `xml:"results"`
		
		Hosts struct {
			Count int `xml:"count"`
			Hosts []struct {
				IP    string `xml:"ip"`
				Asset struct {
					ID string `xml:"asset_id,attr"`
				} `xml:"asset"`
				Start  string `xml:"start"`
				End    string `xml:"end"`
				Port   struct {
					Text string `xml:",chardata"`
				} `xml:"port"`
				Detail []struct {
					Name  string `xml:"name"`
					Value string `xml:"value"`
					Source struct {
						Type        string `xml:"type"`
						Name        string `xml:"name"`
						Description string `xml:"description"`
					} `xml:"source"`
				} `xml:"detail"`
			} `xml:"host"`
		} `xml:"host"`
		
		HostCount struct {
			Text string `xml:",chardata"`
		} `xml:"host_count"`
		
		ResultCount struct {
			Text        string `xml:",chardata"`
			Full        int    `xml:"full"`
			Filtered    int    `xml:"filtered"`
			Warning     int    `xml:"warning"`
			Info        int    `xml:"info"`
			Log         int    `xml:"log"`
			FalsePositive int  `xml:"false_positive"`
		} `xml:"result_count"`
		
		Severity struct {
			Text string `xml:",chardata"`
			Full struct {
				Text string `xml:",chardata"`
			} `xml:"full"`
		} `xml:"severity"`
		
		VulnCount struct {
			Text string `xml:",chardata"`
			Full int    `xml:"full"`
		} `xml:"vulns"`
		
		Errors struct {
			Count  int `xml:"count"`
			Errors []struct {
				Host        string `xml:"host"`
				Port        string `xml:"port"`
				Description string `xml:"description"`
				NVT         struct {
					OID  string `xml:"oid,attr"`
					Name string `xml:"name"`
				} `xml:"nvt"`
			} `xml:"error"`
		} `xml:"errors"`
		
		HostStart string `xml:"host_start"`
		HostEnd   string `xml:"host_end"`
		
		ScanStart struct {
			Text string `xml:",chardata"`
		} `xml:"scan_start"`
		
		ScanEnd struct {
			Text string `xml:",chardata"`
		} `xml:"scan_end"`
		
		Closed  string `xml:"closed_cves"`
		OsCount string `xml:"os_count"`
		Apps    struct {
			Count int `xml:"count"`
		} `xml:"apps"`
		SSLCerts struct {
			Count int `xml:"count"`
		} `xml:"ssl_certs"`
		
	} `xml:"report"`
}

// Struktur JSON output
type ReportData struct {
	ReportID        string           `json:"reportId"`
	FormatID        string           `json:"formatId"`
	ContentType     string           `json:"contentType"`
	Type            string           `json:"type"`
	ScanStart       string           `json:"scanStart"`
	ScanEnd         string           `json:"scanEnd"`
	ScanRunStatus   string           `json:"scanRunStatus"`
	Timestamp       string           `json:"timestamp"`
	Timezone        string           `json:"timezone"`
	TimezoneAbbrev  string           `json:"timezoneAbbrev"`
	
	Task            TaskInfo         `json:"task"`
	ScanConfig      ConfigInfo       `json:"scanConfig"`
	Scanner         ScannerInfo      `json:"scanner"`
	
	Summary         SummaryInfo      `json:"summary"`
	Hosts           []HostInfo       `json:"hosts"`
	Ports           []PortInfo       `json:"ports"`
	Vulnerabilities []VulnInfo       `json:"vulnerabilities"`
	Errors          []ErrorInfo      `json:"errors"`
}

type TaskInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Comment    string     `json:"comment"`
	Target     TargetInfo `json:"target"`
}

type TargetInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ConfigInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type ScannerInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type SummaryInfo struct {
	TotalHosts      int     `json:"totalHosts"`
	TotalPorts      int     `json:"totalPorts"`
	TotalVulns      int     `json:"totalVulns"`
	HighVulns       int     `json:"highVulns"`
	MediumVulns     int     `json:"mediumVulns"`
	LowVulns        int     `json:"lowVulns"`
	LogVulns        int     `json:"logVulns"`
	WarningVulns    int     `json:"warningVulns"`
	InfoVulns       int     `json:"infoVulns"`
	FalsePositives  int     `json:"falsePositives"`
	TotalErrors     int     `json:"totalErrors"`
	MaxSeverity     float64 `json:"maxSeverity"`
	AvgSeverity     float64 `json:"avgSeverity"`
	ClosedCVEs      string  `json:"closedCves"`
	OSCount         string  `json:"osCount"`
	AppsCount       int     `json:"appsCount"`
	SSLCertsCount   int     `json:"sslCertsCount"`
}

type HostInfo struct {
	IP        string       `json:"ip"`
	AssetID   string       `json:"assetId"`
	ScanStart string       `json:"scanStart"`
	ScanEnd   string       `json:"scanEnd"`
	Ports     string       `json:"ports"`
	Details   []HostDetail `json:"details"`
}

type HostDetail struct {
	Name   string     `json:"name"`
	Value  string     `json:"value"`
	Source SourceInfo `json:"source"`
}

type SourceInfo struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type PortInfo struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type VulnInfo struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Host            string         `json:"host"`
	Hostname        string         `json:"hostname"`
	AssetID         string         `json:"assetId"`
	Port            string         `json:"port"`
	Severity        string         `json:"severity"`
	Threat          string         `json:"threat"`
	Description     string         `json:"description"`
	Score           float64        `json:"score"`
	CVSSBase        string         `json:"cvssBase"`
	QoD             QoDInfo        `json:"qod"`
	NVT             NVTInfo        `json:"nvt"`
	CreationTime    string         `json:"creationTime"`
	ModificationTime string        `json:"modificationTime"`
}

type QoDInfo struct {
	Value int    `json:"value"`
	Type  string `json:"type"`
}

type NVTInfo struct {
	OID      string        `json:"oid"`
	Name     string        `json:"name"`
	Family   string        `json:"family"`
	Type     string        `json:"type"`
	Tags     map[string]string `json:"tags"`
	Solution SolutionInfo  `json:"solution"`
	CVEs     []string      `json:"cves"`
	BIDs     []string      `json:"bids"`
	CERTs    []RefInfo     `json:"certs"`
	XRefs    []RefInfo     `json:"xrefs"`
}

type SolutionInfo struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type RefInfo struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ErrorInfo struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	Description string `json:"description"`
	NVTOID      string `json:"nvtOid"`
	NVTName     string `json:"nvtName"`
}

// Parse XML report ke JSON structure
func parseReportXML(xmlStr string) (*ReportData, error) {
	log.Println("DEBUG: Starting comprehensive XML parsing...")

	// Safety: strip any docker compose noise and trim to XML bounds
	clean := extractCleanXML(xmlStr)
	start := strings.Index(clean, "<")
	end := strings.LastIndex(clean, ">")
	if start >= 0 && end > start {
		clean = clean[start : end+1]
	}

	type countWrapper struct {
		Count int `xml:"count"`
	}

	type countPair struct {
		Full     int `xml:"full"`
		Filtered int `xml:"filtered"`
	}

	type resultCount struct {
		Text          string    `xml:",chardata"`
		Full          int       `xml:"full"`
		Filtered      int       `xml:"filtered"`
		Critical      countPair `xml:"critical"`
		High          countPair `xml:"high"`
		Medium        countPair `xml:"medium"`
		Low           countPair `xml:"low"`
		Log           countPair `xml:"log"`
		Warning       countPair `xml:"warning"`
		Info          countPair `xml:"info"`
		FalsePositive countPair `xml:"false_positive"`
	}

	type severitySection struct {
		Full     string `xml:"full"`
		Filtered string `xml:"filtered"`
	}

	type portsSection struct {
		Count int `xml:"count"`
		Ports []struct {
			Host     string `xml:"host"`
			Text     string `xml:",chardata"`
			Severity string `xml:"severity"`
			Threat   string `xml:"threat"`
		} `xml:"port"`
	}

	type resultHost struct {
		Text     string `xml:",chardata"`
		Hostname string `xml:"hostname"`
		Asset    struct {
			ID string `xml:"asset_id,attr"`
		} `xml:"asset"`
	}

	type nvtRefs struct {
		Ref []struct {
			Type string `xml:"type,attr"`
			ID   string `xml:"id,attr"`
		} `xml:"ref"`
	}

	type nvtCerts struct {
		CertRef []struct {
			Type string `xml:"type,attr"`
			ID   string `xml:"id,attr"`
		} `xml:"cert_ref"`
	}

	type nvtXrefs struct {
		Xref []struct {
			Type string `xml:"type,attr"`
			ID   string `xml:"id,attr"`
		} `xml:"xref"`
	}

	type resultsSection struct {
		Results []struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
			Host resultHost
			Port string `xml:"port"`
			NVT  struct {
				OID      string `xml:"oid,attr"`
				Type     string `xml:"type"`
				Name     string `xml:"name"`
				Family   string `xml:"family"`
				CVSSBase string `xml:"cvss_base"`
				Tags     string `xml:"tags"`
				Refs     nvtRefs `xml:"refs"`
				Cert     struct {
					CertRef []struct {
						Type string `xml:"type,attr"`
						ID   string `xml:"id,attr"`
					} `xml:"cert_ref"`
				} `xml:"cert"`
				Solution struct {
					Type string `xml:"type,attr"`
					Text string `xml:",chardata"`
				} `xml:"solution"`
				Xrefs nvtXrefs `xml:"xrefs"`
			} `xml:"nvt"`
			Threat      string `xml:"threat"`
			Severity    string `xml:"severity"`
			QoD         struct {
				Value int    `xml:"value"`
				Type  string `xml:"type"`
			} `xml:"qod"`
			Description      string `xml:"description"`
			CreationTime     string `xml:"creation_time"`
			ModificationTime string `xml:"modification_time"`
		} `xml:"result"`
	} 

	type innerTask struct {
		ID      string `xml:"id,attr"`
		Name    string `xml:"name"`
		Comment string `xml:"comment"`
		Target  struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"target"`
		Progress string `xml:"progress"`
	}

	type errorsSection struct {
		Count  int `xml:"count"`
		Errors []struct {
			Host struct {
				Text  string `xml:",chardata"`
				Asset struct {
					ID string `xml:"asset_id,attr"`
				} `xml:"asset"`
			} `xml:"host"`
			Port        string `xml:"port"`
			Description string `xml:"description"`
			NVT         struct {
				OID  string `xml:"oid,attr"`
				Name string `xml:"name"`
			} `xml:"nvt"`
		} `xml:"error"`
	}

	type innerReport struct {
		ScanRunStatus string        `xml:"scan_run_status"`
		Hosts         countWrapper  `xml:"hosts"`
		ClosedCVEs    countWrapper  `xml:"closed_cves"`
		Vulns         countWrapper  `xml:"vulns"`
		OS            countWrapper  `xml:"os"`
		Apps          countWrapper  `xml:"apps"`
		SSLCerts      countWrapper  `xml:"ssl_certs"`
		Task          innerTask     `xml:"task"`
		Timestamp     string        `xml:"timestamp"`
		ScanStart     string        `xml:"scan_start"`
		ScanEnd       string        `xml:"scan_end"`
		Timezone      string        `xml:"timezone"`
		TimezoneAbbrev string       `xml:"timezone_abbrev"`
		Ports         portsSection  `xml:"ports"`
		Results       resultsSection `xml:"results"`
		ResultCount   resultCount   `xml:"result_count"`
		Severity      severitySection `xml:"severity"`
		Errors        errorsSection `xml:"errors"`
	}

	type outerReport struct {
		ID          string `xml:"id,attr"`
		FormatID    string `xml:"format_id,attr"`
		ConfigID    string `xml:"config_id,attr"`
		Extension   string `xml:"extension,attr"`
		ContentType string `xml:"content_type,attr"`
		CreationTime     string `xml:"creation_time"`
		ModificationTime string `xml:"modification_time"`
		Task struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"task"`
		Inner innerReport `xml:"report"`
	}

	type getReportsResponse struct {
		XMLName xml.Name    `xml:"get_reports_response"`
		Report  outerReport `xml:"report"`
	}

	var resp getReportsResponse
	if err := xml.Unmarshal([]byte(clean), &resp); err != nil {
		log.Printf("ERROR: XML unmarshal failed: %v", err)
		return nil, err
	}

	outer := resp.Report
	inner := resp.Report.Inner

	reportData := &ReportData{
		ReportID:       outer.ID,
		FormatID:       outer.FormatID,
		ContentType:    outer.ContentType,
		Type:           "openvas",
		ScanStart:      inner.ScanStart,
		ScanEnd:        inner.ScanEnd,
		ScanRunStatus:  inner.ScanRunStatus,
		Timestamp:      inner.Timestamp,
		Timezone:       inner.Timezone,
		TimezoneAbbrev: inner.TimezoneAbbrev,
		Task: TaskInfo{
			ID:      inner.Task.ID,
			Name:    inner.Task.Name,
			Comment: inner.Task.Comment,
			Target: TargetInfo{
				ID:   inner.Task.Target.ID,
				Name: inner.Task.Target.Name,
			},
		},
		ScanConfig:      ConfigInfo{},
		Scanner:         ScannerInfo{},
		Summary:         SummaryInfo{},
		Hosts:           make([]HostInfo, 0),
		Ports:           make([]PortInfo, 0),
		Vulnerabilities: make([]VulnInfo, 0),
		Errors:          make([]ErrorInfo, 0),
	}

	reportData.Summary.TotalHosts = inner.Hosts.Count
	reportData.Summary.TotalPorts = inner.Ports.Count
	reportData.Summary.TotalErrors = inner.Errors.Count
	reportData.Summary.AppsCount = inner.Apps.Count
	reportData.Summary.SSLCertsCount = inner.SSLCerts.Count
	reportData.Summary.ClosedCVEs = strconv.Itoa(inner.ClosedCVEs.Count)
	reportData.Summary.OSCount = strconv.Itoa(inner.OS.Count)

	// Prefer result_count if present
	reportData.Summary.HighVulns = inner.ResultCount.High.Full
	reportData.Summary.MediumVulns = inner.ResultCount.Medium.Full
	reportData.Summary.LowVulns = inner.ResultCount.Low.Full
	reportData.Summary.LogVulns = inner.ResultCount.Log.Full
	reportData.Summary.WarningVulns = inner.ResultCount.Warning.Full
	reportData.Summary.InfoVulns = inner.ResultCount.Info.Full
	reportData.Summary.FalsePositives = inner.ResultCount.FalsePositive.Full

	// Ports
	for _, p := range inner.Ports.Ports {
		portText := strings.TrimSpace(p.Text)
		protocol := ""
		if parts := strings.SplitN(portText, "/", 2); len(parts) == 2 {
			protocol = strings.TrimSpace(parts[1])
		}
		reportData.Ports = append(reportData.Ports, PortInfo{
			Host:     strings.TrimSpace(p.Host),
			Port:     portText,
			Protocol: protocol,
		})
	}

	// Vulnerabilities
	var totalSeverity float64
	for _, r := range inner.Results.Results {
		score, _ := strconv.ParseFloat(strings.TrimSpace(r.Severity), 64)
		tags := parseNVTTags(r.NVT.Tags)

		cves := make([]string, 0)
		bids := make([]string, 0)
		for _, ref := range r.NVT.Refs.Ref {
			switch strings.ToLower(ref.Type) {
			case "cve":
				cves = append(cves, ref.ID)
			case "bid":
				bids = append(bids, ref.ID)
			}
		}

		certs := make([]RefInfo, 0)
		for _, cert := range r.NVT.Cert.CertRef {
			certs = append(certs, RefInfo{Type: cert.Type, ID: cert.ID})
		}

		xrefs := make([]RefInfo, 0)
		for _, x := range r.NVT.Xrefs.Xref {
			xrefs = append(xrefs, RefInfo{Type: x.Type, ID: x.ID})
		}

		vuln := VulnInfo{
			ID:               r.ID,
			Name:             r.Name,
			Host:             strings.TrimSpace(r.Host.Text),
			Hostname:         strings.TrimSpace(r.Host.Hostname),
			AssetID:          r.Host.Asset.ID,
			Port:             strings.TrimSpace(r.Port),
			Severity:         strings.TrimSpace(r.Threat),
			Threat:           strings.TrimSpace(r.Threat),
			Description:      strings.TrimSpace(r.Description),
			Score:            score,
			CVSSBase:         strings.TrimSpace(r.NVT.CVSSBase),
			CreationTime:     r.CreationTime,
			ModificationTime: r.ModificationTime,
			QoD: QoDInfo{Value: r.QoD.Value, Type: strings.TrimSpace(r.QoD.Type)},
			NVT: NVTInfo{
				OID:    r.NVT.OID,
				Name:   r.NVT.Name,
				Family: r.NVT.Family,
				Type:   r.NVT.Type,
				Tags:   tags,
				Solution: SolutionInfo{
					Type: strings.TrimSpace(r.NVT.Solution.Type),
					Text: strings.TrimSpace(r.NVT.Solution.Text),
				},
				CVEs:  cves,
				BIDs:  bids,
				CERTs: certs,
				XRefs: xrefs,
			},
		}

		reportData.Vulnerabilities = append(reportData.Vulnerabilities, vuln)

		if score > reportData.Summary.MaxSeverity {
			reportData.Summary.MaxSeverity = score
		}
		totalSeverity += score
	}

	reportData.Summary.TotalVulns = len(reportData.Vulnerabilities)
	if reportData.Summary.TotalVulns > 0 {
		reportData.Summary.AvgSeverity = totalSeverity / float64(reportData.Summary.TotalVulns)
	}

	// If result_count wasn't populated (older schema), compute severity buckets from threat values
	if reportData.Summary.HighVulns == 0 && reportData.Summary.MediumVulns == 0 && reportData.Summary.LowVulns == 0 {
		for _, v := range reportData.Vulnerabilities {
			switch v.Threat {
			case "High":
				reportData.Summary.HighVulns++
			case "Medium":
				reportData.Summary.MediumVulns++
			case "Low":
				reportData.Summary.LowVulns++
			case "Log":
				reportData.Summary.LogVulns++
			}
		}
	}

	// Errors
	for _, e := range inner.Errors.Errors {
		reportData.Errors = append(reportData.Errors, ErrorInfo{
			Host:        strings.TrimSpace(e.Host.Text),
			Port:        strings.TrimSpace(e.Port),
			Description: strings.TrimSpace(e.Description),
			NVTOID:      strings.TrimSpace(e.NVT.OID),
			NVTName:     strings.TrimSpace(e.NVT.Name),
		})
	}

	log.Printf("DEBUG: Parsed %d ports, %d vulnerabilities, %d errors", len(reportData.Ports), len(reportData.Vulnerabilities), len(reportData.Errors))
	return reportData, nil
}

// Parse NVT tags string into map
func parseNVTTags(tagsStr string) map[string]string {
	tags := make(map[string]string)
	if tagsStr == "" {
		return tags
	}
	
	// Tags biasanya format: key=value|key=value
	pairs := strings.Split(tagsStr, "|")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			tags[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	
	return tags
}

// Helper function untuk truncate string untuk debugging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}

// Helper function untuk extract tag value dari XML
func extractXMLTag(xmlStr, tagName string) string {
	re := regexp.MustCompile(`<` + tagName + `>([^<]*)<\/` + tagName + `>`)
	matches := re.FindStringSubmatch(xmlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// Helper function untuk extract attribute dari XML tag
func extractXMLAttribute(xmlStr, tagName, attrName string) string {
	re := regexp.MustCompile(`<` + tagName + `[^>]*` + attrName + `="([^"]*)"`)
	matches := re.FindStringSubmatch(xmlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// Helper function untuk count total results/vulnerabilities
func extractXMLResultCount(xmlStr string) int {
	re := regexp.MustCompile(`<result id=`)
	matches := re.FindAllString(xmlStr, -1)
	return len(matches)
}

// Helper function untuk count vulnerabilities by severity
func countVulnsBySeverity(xmlStr, severity string) int {
	// OpenVAS biasanya punya <threat>High/Medium/Low</threat>
	re := regexp.MustCompile(`<threat>` + severity + `</threat>`)
	matches := re.FindAllString(xmlStr, -1)
	return len(matches)
}

// Helper function to clean docker compose output and extract only XML
func extractCleanXML(output string) string {
	log.Println("DEBUG: extractCleanXML called")
	
	// Find the start of XML (usually starts with <)
	startIdx := strings.Index(output, "<")
	if startIdx == -1 {
		log.Println("ERROR: No XML found in output")
		return output
	}

	cleanXML := output[startIdx:]
	log.Printf("DEBUG: Extracted clean XML, length: %d bytes", len(cleanXML))
	return cleanXML

}

// Helper function untuk extract ID dari XML response
func extractIDFromXML(xmlResponse string) string {
	log.Println("DEBUG: extractIDFromXML called")

	// Clean docker compose output first
	cleanXML := extractCleanXML(xmlResponse)

	// Simple parsing untuk ambil id="..."
	// Response biasanya: <create_target_response status="201" id="uuid-here" ...>
	startIdx := -1
	for i := 0; i < len(cleanXML)-4; i++ {
		if cleanXML[i:i+4] == `id="` {
			startIdx = i + 4
			log.Printf("DEBUG: Found 'id=\"' at position %d", i)
			break
		}
	}
	if startIdx == -1 {
		log.Println("ERROR: Could not find 'id=\"' in XML response")
		return ""
	}

	endIdx := -1
	for i := startIdx; i < len(cleanXML); i++ {
		if cleanXML[i] == '"' {
			endIdx = i
			log.Printf("DEBUG: Found closing quote at position %d", i)
			break
		}
	}
	if endIdx == -1 {
		log.Println("ERROR: Could not find closing quote for ID")
		return ""
	}

	extractedID := cleanXML[startIdx:endIdx]
	log.Printf("DEBUG: Extracted ID: %s", extractedID)
	return extractedID
}

func (ov *OpenVasRoutes) SetupRoutes(r *gin.RouterGroup) {
	// Route untuk cek koneksi
	r.GET("/openvas/version", ov.GetVersion)
	// Route untuk mulai scan
	r.POST("/openvas/scan", ov.StartScan)
	// Route untuk cek progress scan
	r.GET("/openvas/task/:taskId/status", ov.GetTaskStatus)
	// Route untuk ambil hasil scan
	r.GET("/openvas/report/:reportId", ov.GetScanReport)
}
