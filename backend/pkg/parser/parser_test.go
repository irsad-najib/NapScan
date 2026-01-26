package parser

import (
	"encoding/json"
	"testing"
)

func TestNmapParser(t *testing.T) {
	parser := NewNmapParser()

	// Mock Nmap output
	rawJSON := `{
		"hosts": [
			{
				"ports": [
					{"portid": 80, "service": {"name": "http"}},
					{"portid": 22, "service": {"name": "ssh"}}
				]
			}
		]
	}`

	var rawResult map[string]interface{}
	json.Unmarshal([]byte(rawJSON), &rawResult)

	parsed, err := parser.Parse(rawResult)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	normalized, err := parser.Normalize(parsed)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(normalized.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(normalized.Findings))
	}

	if normalized.Scanner != "nmap" {
		t.Errorf("Expected scanner nmap, got %s", normalized.Scanner)
	}
}

func TestNucleiParser(t *testing.T) {
	parser := NewNucleiParser()

	// Mock Nuclei output (array)
	rawJSON := `[
		{
			"info": {
				"name": "Test Vulnerability",
				"severity": "critical"
			},
			"matched-at": "https://example.com/vuln"
		}
	]`

	var rawResult interface{}
	json.Unmarshal([]byte(rawJSON), &rawResult)

	parsed, err := parser.Parse(rawResult)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	normalized, err := parser.Normalize(parsed)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(normalized.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(normalized.Findings))
	}

	if normalized.NormalizedSeverity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got %s", normalized.NormalizedSeverity)
	}
}
