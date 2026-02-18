package parser

// ScannerParser defines the interface that all scanner parsers must implement
type ScannerParser interface {
	Parse(rawResult interface{}) (*ParsedResult, error)
}

// ParsedResult represents the intermediate parsed data from a scanner
type ParsedResult struct {
	Findings []Finding
	Metadata map[string]interface{}
}

// Finding represents a single security finding from any scanner
type Finding struct {
	Source      string      `json:"source"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Method      string      `json:"method"`       // e.g., "GET", "POST", or "TCP"
	ReferenceID string      `json:"reference_id"` // CVE-ID, CWE-ID, or other ref
	Service     string      `json:"service"`      // Service name (e.g., "ssh", "http")
	Product     string      `json:"product"`      // Product name (e.g., "OpenSSH")
	Version     string      `json:"version"`      // Version string
	Severity    string      `json:"severity"`     // Original severity from tool (unnormalized)
	Target      string      `json:"target"`
	RawData     interface{} `json:"raw_data"`
}
