package parser

import "napscan-be/internal/models"

// ScannerParser defines the interface that all scanner parsers must implement
type ScannerParser interface {
	Parse(rawResult interface{}) (*ParsedResult, error)
	Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error)
	ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error)
}

// ParsedResult represents the intermediate parsed data from a scanner
type ParsedResult struct {
	Findings []Finding
	Metadata map[string]interface{}
}

// Finding represents a single security finding from any scanner
type Finding struct {
	Severity    string
	Title       string
	Description string
	Target      string
	RawData     interface{}
}
