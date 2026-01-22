package models

import (
	"bytes"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// BatchStatus indicates the progress of the batch
type BatchStatus string

const (
	BatchStatusProcessing BatchStatus = "processing"
	BatchStatusComplete   BatchStatus = "complete"
)

// Batch represents the aggregated state of multiple API requests
type Batch struct {
	UserID            string                 `json:"user_id" gorm:"type:varchar(191);index"`
	BatchID           string                 `json:"batch_id" gorm:"primaryKey;type:varchar(191)"`
	ExpectedCount     int                    `json:"expected_count"`
	ReceivedCount     int                    `json:"received_count"`
	ResultsRaw        []byte                 `json:"-" gorm:"column:results"`
	Results           map[string]interface{} `json:"results" gorm:"-"`
	ScanResults       []ScanResult           `json:"-" gorm:"foreignKey:BatchID;references:BatchID"`   // Relation for getting target (Nmap/etc)
	UploadedFiles     []UploadedFile         `json:"-" gorm:"foreignKey:BatchID;references:BatchID"`   // Relation for getting target (APK)
	Status            BatchStatus            `json:"status" gorm:"type:varchar(32)"`
	AnalysisResultRaw []byte                 `json:"-" gorm:"column:analysis_result"`
	AnalysisResult    interface{}            `json:"analysis_result,omitempty" gorm:"-"`
	CreatedAt         time.Time              `json:"created_at"`
}

func (b *Batch) BeforeSave(tx *gorm.DB) (err error) {
	if b.Results != nil {
		b.ResultsRaw, err = json.Marshal(b.Results)
		if err != nil {
			return err
		}
	}
	if b.AnalysisResult != nil {
		b.AnalysisResultRaw, err = json.Marshal(b.AnalysisResult)
	}
	return
}

func (b *Batch) AfterFind(tx *gorm.DB) (err error) {
	if b.ResultsRaw != nil {
		decoder := json.NewDecoder(bytes.NewReader(b.ResultsRaw))
		decoder.UseNumber()
		err = decoder.Decode(&b.Results)
		if err != nil {
			return err
		}
	}
	if b.AnalysisResultRaw != nil {
		decoder := json.NewDecoder(bytes.NewReader(b.AnalysisResultRaw))
		decoder.UseNumber()
		err = decoder.Decode(&b.AnalysisResult)
	}
	return
}

// BatchRequest represents the input for fan-in endpoints
type BatchRequest struct {
	Data string `json:"data"`
}

// BatchResponse returns the status of an analysis
type BatchResponse struct {
	Status         BatchStatus `json:"status"`
	AnalysisResult interface{} `json:"result,omitempty"`
	BatchID        string      `json:"batch_id"`
}

// ScanReport represents the complete security scan analysis
type ScanReport struct {
	Summary          ScanSummary           `json:"summary"`
	NetworkAnalysis  NetworkAnalysis       `json:"network_analysis"`
	Vulnerabilities  []Vulnerability       `json:"vulnerabilities"`
	Recommendations  []Recommendation      `json:"recommendations"`
	RiskScore        int                   `json:"risk_score"`
	Timestamp        time.Time             `json:"timestamp"`
}

// ScanSummary provides overview of the scan
type ScanSummary struct {
	TotalHosts       int    `json:"total_hosts"`
	TotalOpenPorts   int    `json:"total_open_ports"`
	TotalServices    int    `json:"total_services"`
	HighRiskPorts    int    `json:"high_risk_ports"`
	MediumRiskPorts  int    `json:"medium_risk_ports"`
	LowRiskPorts     int    `json:"low_risk_ports"`
	ScanDuration     string `json:"scan_duration"`
}

// NetworkAnalysis contains detailed network information
type NetworkAnalysis struct {
	Hosts           []HostAnalysis  `json:"hosts"`
	OpenPorts       []PortAnalysis  `json:"open_ports"`
	Services        []ServiceInfo   `json:"services"`
}

// HostAnalysis represents analyzed host information
type HostAnalysis struct {
	IPAddress       string         `json:"ip_address"`
	Hostname        string         `json:"hostname,omitempty"`
	OpenPortsCount  int            `json:"open_ports_count"`
	RiskLevel       string         `json:"risk_level"`
}

// PortAnalysis represents analyzed port information
type PortAnalysis struct {
	Port            string `json:"port"`
	Protocol        string `json:"protocol"`
	State           string `json:"state"`
	Service         string `json:"service"`
	RiskLevel       string `json:"risk_level"`
	RiskReason      string `json:"risk_reason,omitempty"`
}

// ServiceInfo represents service details
type ServiceInfo struct {
	Name            string `json:"name"`
	Port            string `json:"port"`
	Version         string `json:"version,omitempty"`
	Count           int    `json:"count"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	Description     string   `json:"description"`
	AffectedPorts   []string `json:"affected_ports"`
	CVE             string   `json:"cve,omitempty"`
	CVSS            float64  `json:"cvss,omitempty"`
}

// Recommendation represents security recommendation
type Recommendation struct {
	Priority        string   `json:"priority"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	AffectedItems   []string `json:"affected_items"`
	Remediation     string   `json:"remediation"`
}

// BatchSummaryResponse represents a summarized view of a batch for lists
type BatchSummaryResponse struct {
	BatchID     string      `json:"batch_id"`
	Target      string      `json:"target"`
	RiskScore   int         `json:"risk_score"`
	RiskDetails interface{} `json:"risk_details,omitempty"`
	Status      string      `json:"status"`
	Timestamp   time.Time   `json:"timestamp"`
}
