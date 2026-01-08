package service

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Structures for XML Parsing

// Task Parsing
type GVMDTaskResponse struct {
	XMLName xml.Name `xml:"get_tasks_response"`
	Task    GVMDTask `xml:"task"`
}

type GVMDTask struct {
	Status     string         `xml:"status" json:"status"`
	Progress   string         `xml:"progress" json:"progress"`
	LastReport GVMDLastReport `xml:"last_report" json:"last_report"`
}

type GVMDLastReport struct {
	Report GVMDReportRef `xml:"report" json:"report"`
}

type GVMDReportRef struct {
	ID string `xml:"id,attr" json:"id"`
}

// Report Parsing
type GVMDReportResponse struct {
	XMLName xml.Name   `xml:"get_reports_response"`
	Report  GVMDReportWrapper `xml:"report"`
}

type GVMDReportWrapper struct {
    InnerReport GVMDReportContent `xml:"report"`
}

type GVMDReportContent struct {
	ScanRunStatus string       `xml:"scan_run_status" json:"scan_run_status"`
	Results       GVMDResults  `xml:"results" json:"results"`
}

type GVMDResults struct {
	Result []GVMDResult `xml:"result" json:"result"`
}

type GVMDResult struct {
	Name        string  `xml:"name" json:"name"`
	Host        string  `xml:"host" json:"host"`
	Port        string  `xml:"port" json:"port"`
	Threat      string  `xml:"threat" json:"threat"`
	Severity    string  `xml:"severity" json:"severity"`
	Qod         string  `xml:"qod" json:"qod"`
	Description string  `xml:"description" json:"description"`
	NVT         GVMDNVT `xml:"nvt" json:"nvt"`
}

type GVMDNVT struct {
	OID      string `xml:"oid,attr" json:"oid"`
	Name     string `xml:"name" json:"name"`
	Family   string `xml:"family" json:"family"`
	CVSSBase string `xml:"cvss_base" json:"cvss_base"`
	Tags     string `xml:"tags" json:"tags"`
}

type OpenVASService struct{}

func NewOpenVASService() *OpenVASService {
	return &OpenVASService{}
}

func (s *OpenVASService) gvmSocketPath() string {
	if v := strings.TrimSpace(os.Getenv("OPENVAS_GVMD_SOCKET")); v != "" {
		return v
	}
	return "/var/run/gvmd/gvmd.sock"
}

func (s *OpenVASService) gmpUsername() string {
	if v := strings.TrimSpace(os.Getenv("OPENVAS_GMP_USERNAME")); v != "" {
		return v
	}
	return "admin"
}

func (s *OpenVASService) gmpPassword() string {
	if v := strings.TrimSpace(os.Getenv("OPENVAS_GMP_PASSWORD")); v != "" {
		return v
	}
	return "admin"
}

func (s *OpenVASService) resolveComposePath() (string, error) {
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
	// Fallbacks
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(cwd, "docker-compose.yml"),
		filepath.Join(cwd, "..", "docker-compose.yml"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	// Return empty to imply we might run locally without compose
	// But sticking to the original logic which returned error if not found?
	// The original logic returned error. We'll return error if we can't find it AND we are not in a container
	// But let's simplify: just return empty string and handle it in RunGVMCLI
	return "", fmt.Errorf("could not find docker-compose.yml for OpenVAS")
}

func (s *OpenVASService) RunGVMCLI(ctx context.Context, xmlCommand string) ([]byte, error) {
	// 1. Try running inside container if socket exists
	socketPath := s.gvmSocketPath()
	if _, err := os.Stat(socketPath); err == nil {
		gvmcli := "gvm-cli"
		args := []string{
			"--gmp-username", s.gmpUsername(),
			"--gmp-password", s.gmpPassword(),
			"socket",
			"--socketpath", socketPath,
			"--xml", xmlCommand,
		}

		// Use runuser if running as root in container (common in some setups)
		if os.Geteuid() == 0 {
			runuserPath, err := exec.LookPath("runuser")
			if err == nil {
				runAs := os.Getenv("OPENVAS_RUN_USER")
				if runAs == "" {
					runAs = "_gvm"
				}
				// Retry mechanism for Connection refused
				maxRetries := 15
				for i := 0; i < maxRetries; i++ {
					cmd := exec.CommandContext(ctx, runuserPath, append([]string{"-u", runAs, "--", gvmcli}, args...)...)
					out, err := cmd.CombinedOutput()
					if err == nil {
						return out, nil
					}
					// If error indicates connection refused, wait and retry
					outStr := string(out)
					if strings.Contains(outStr, "Connection refused") || strings.Contains(outStr, "No such file") || strings.Contains(outStr, "Resource temporarily unavailable") {
						if i < maxRetries-1 {
							time.Sleep(2 * time.Second)
							continue
						}
					}
					return out, fmt.Errorf("gvm-cli error after %d retries: %w, output: %s", maxRetries, err, outStr)
				}
			}
		}

		cmd := exec.CommandContext(ctx, gvmcli, args...)
		return cmd.CombinedOutput()
	}

	// 2. Fallback: docker compose
	composePath, err := s.resolveComposePath()
	if err != nil {
		return nil, err
	}
	
	cmd := exec.CommandContext(ctx,
		"docker", "compose", "-f", composePath,
		"run", "--rm", "gvm-tools",
		"gvm-cli",
		"--gmp-username", s.gmpUsername(),
		"--gmp-password", s.gmpPassword(),
		"socket",
		"--xml", xmlCommand,
	)
	return cmd.CombinedOutput()
}

func (s *OpenVASService) extractCleanXML(output string) string {
	startIdx := strings.Index(output, "<")
	if startIdx == -1 {
		return output
	}
	return output[startIdx:]
}

func (s *OpenVASService) extractIDFromXML(xmlResponse string) string {
	cleanXML := s.extractCleanXML(xmlResponse)
	// Simple search for id="..."
	startIdx := -1
	for i := 0; i < len(cleanXML)-4; i++ {
		if cleanXML[i:i+4] == `id="` {
			startIdx = i + 4
			break
		}
	}
	if startIdx == -1 {
		return ""
	}
	
	endIdx := -1
	for i := startIdx; i < len(cleanXML); i++ {
		if cleanXML[i] == '"' {
			endIdx = i
			break
		}
	}
	if endIdx == -1 {
		return ""
	}
	return cleanXML[startIdx:endIdx]
}

func (s *OpenVASService) GetVersion(ctx context.Context) (string, error) {
	output, err := s.RunGVMCLI(ctx, "<get_version/>")
	if err != nil {
		return "", err
	}
	return s.extractCleanXML(string(output)), nil
}

func (s *OpenVASService) StartScan(ctx context.Context, target string) (map[string]interface{}, error) {
	targetName := "Scan-" + target + "-" + time.Now().Format("20060102-150405")
	
	// 1. Create Target
	portListID := "33d0cd82-57c6-11e1-8ed1-406186ea4fc5" // All IANA configured TCP
	createTargetXML := fmt.Sprintf(`<create_target><name>%s</name><hosts>%s</hosts><port_list id="%s"/></create_target>`, 
		targetName, target, portListID)
	
	out, err := s.RunGVMCLI(ctx, createTargetXML)
	if err != nil {
		return nil, fmt.Errorf("failed to create target: %w, output: %s", err, string(out))
	}
	
	targetID := s.extractIDFromXML(string(out))
	if targetID == "" {
		return nil, fmt.Errorf("failed to extract target ID, output: %s", string(out))
	}

	// 2. Create Task
	configID := "daba56c8-73ec-11df-a475-002264764cea" // Full and fast
	scannerID := "08b69003-5fc2-4037-a479-93b440211c73" // OpenVAS Default
	createTaskXML := fmt.Sprintf(`<create_task><name>%s</name><target id="%s"/><config id="%s"/><scanner id="%s"/></create_task>`,
		targetName, targetID, configID, scannerID)
		
	out, err = s.RunGVMCLI(ctx, createTaskXML)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %w, output: %s", err, string(out))
	}
	
	taskID := s.extractIDFromXML(string(out))
	if taskID == "" {
		return nil, fmt.Errorf("failed to extract task ID, output: %s", string(out))
	}

	// 3. Start Task
	startTaskXML := fmt.Sprintf(`<start_task task_id="%s"/>`, taskID)
	out, err = s.RunGVMCLI(ctx, startTaskXML)
	if err != nil {
		return nil, fmt.Errorf("failed to start task: %w, output: %s", err, string(out))
	}

	return map[string]interface{}{
		"message":  "OpenVAS scan started successfully",
		"target":   target,
		"targetID": targetID,
		"taskID":   taskID,
		"scanName": targetName,
		"status":   "running",
	}, nil
}

func (s *OpenVASService) GetTaskStatus(ctx context.Context, taskID string) (*GVMDTask, error) {
	xmlCmd := fmt.Sprintf(`<get_tasks task_id="%s" details="1"/>`, taskID)
	out, err := s.RunGVMCLI(ctx, xmlCmd)
	if err != nil {
		return nil, err
	}

	cleanXML := s.extractCleanXML(string(out))
	var resp GVMDTaskResponse
	if err := xml.Unmarshal([]byte(cleanXML), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse task XML: %w", err)
	}

	// Determine progress
	// Sometimes progress is -1 when waiting
	p, _ := strconv.Atoi(resp.Task.Progress)
	if p < 0 {
		resp.Task.Progress = "0"
	}
	
	return &resp.Task, nil
}

func (s *OpenVASService) GetScanReport(ctx context.Context, reportID string) (*GVMDReportContent, error) {
	// Use XML format
	xmlCmd := fmt.Sprintf(`<get_reports report_id="%s" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" details="1"/>`, reportID)
	out, err := s.RunGVMCLI(ctx, xmlCmd)
	if err != nil {
		return nil, err
	}

	cleanXML := s.extractCleanXML(string(out))
	var resp GVMDReportResponse
	if err := xml.Unmarshal([]byte(cleanXML), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse report XML: %w", err)
	}

	return &resp.Report.InnerReport, nil
}
