package scanner

import (
	"context"
	"time"
)

// Scanner defines the interface that all security scanning tools must implement
type Scanner interface {
	// Name returns the unique identifier for this scanner
	Name() string
	
	// Execute runs the scan with the given configuration
	// Returns raw result data and any error encountered
	Execute(ctx context.Context, config ScanConfig) (interface{}, error)
	
	// Normalize converts raw scanner output to unified vulnerability format
	Normalize(rawResult interface{}) ([]Vulnerability, error)
	
	// Validate checks if the scanner is properly configured and available
	Validate() error
}

// ScanConfig contains common configuration for all scanners
type ScanConfig struct {
	// Target can be IP, domain, URL, or file path depending on scanner
	Target string `json:"target"`
	
	// Options contains scanner-specific configuration
	Options map[string]interface{} `json:"options,omitempty"`
	
	// Timeout for scan execution
	Timeout time.Duration `json:"timeout"`
	
	// UserID for tracking and authorization
	UserID string `json:"user_id"`
}

// Vulnerability represents a normalized security finding
type Vulnerability struct {
	// Unique identifier for this vulnerability
	ID string `json:"id"`
	
	// Human-readable title
	Title string `json:"title"`
	
	// Severity level: info, low, medium, high, critical
	Severity Severity `json:"severity"`
	
	// Detailed description of the vulnerability
	Description string `json:"description"`
	
	// Asset(s) affected (IP:port, URL, file path, etc.)
	AffectedAsset []string `json:"affected_asset"`
	
	// Source tool that discovered this vulnerability
	SourceTool string `json:"source_tool"`
	
	// Evidence/proof of the vulnerability
	Evidence string `json:"evidence,omitempty"`
	
	// Recommended remediation steps
	Remediation string `json:"remediation,omitempty"`
	
	// CVE identifier if applicable
	CVE string `json:"cve,omitempty"`
	
	// CVSS score if applicable
	CVSS float64 `json:"cvss,omitempty"`
	
	// CWE identifier if applicable
	CWE string `json:"cwe,omitempty"`
	
	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Severity represents the severity level of a vulnerability
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ScanStatus represents the current state of a scan job
type ScanStatus string

const (
	StatusPending  ScanStatus = "pending"
	StatusRunning  ScanStatus = "running"
	StatusSuccess  ScanStatus = "success"
	StatusFailed   ScanStatus = "failed"
	StatusCanceled ScanStatus = "canceled"
)

// ScanJob represents a single scanner execution within a batch
type ScanJob struct {
	ID           string                 `json:"id"`
	BatchID      string                 `json:"batch_id"`
	ToolName     string                 `json:"tool_name"`
	Status       ScanStatus             `json:"status"`
	Config       ScanConfig             `json:"config"`
	StartTime    *time.Time             `json:"start_time,omitempty"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Duration     time.Duration          `json:"duration,omitempty"`
	RawResult    interface{}            `json:"raw_result,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// ScannerRegistry manages available scanners
type ScannerRegistry interface {
	// Register adds a scanner to the registry
	Register(scanner Scanner) error
	
	// Get retrieves a scanner by name
	Get(name string) (Scanner, error)
	
	// List returns all registered scanner names
	List() []string
	
	// ValidateAll checks if all scanners are properly configured
	ValidateAll() map[string]error
}
