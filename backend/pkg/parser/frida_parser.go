package parser

import (
	"fmt"
	"strings"
)

type FridaParser struct{}

func NewFridaParser() *FridaParser {
	return &FridaParser{}
}

// Keywords for detection hint only, NOT scoring
var fridaInterestingKeywords = []string{
	"ssl unpin", "unpinning", "bypass", "hooked", "hook success",
	"anti-debug", "root bypass", "jailbreak bypass",
}

func (p *FridaParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("frida result is not a map")
	}

	// Unwrap "frida" key if present (persistence wrapper)
	if inner, ok := resultMap["frida"].(map[string]interface{}); ok {
		resultMap = inner
	}

	// 1. Check Status
	status, _ := resultMap["status"].(string)
	result.Metadata["status"] = status

	// 2. Parse Events (New Schema)
	if events, ok := resultMap["events"].([]interface{}); ok {
		for _, e := range events {
			if eMap, ok := e.(map[string]interface{}); ok {
				eventType, _ := eMap["event"].(string)
				dataMap, _ := eMap["data"].(map[string]interface{})

				// Construct description
				desc := fmt.Sprintf("Event: %s", eventType)
				if len(dataMap) > 0 {
					// simple serialization for desc
					desc += fmt.Sprintf(" Data: %v", dataMap)
				}

				// Check for specific interesting events
				if eventType == "hook_installed" {
					desc = "Hook installed"
					if cls, ok := dataMap["class"]; ok {
						desc += fmt.Sprintf(" on %v", cls)
					}
					if mjd, ok := dataMap["method"]; ok {
						desc += fmt.Sprintf(".%v", mjd)
					}
				}

				// Keyword matching for detection
				lowerDesc := strings.ToLower(desc)
				severity := "info"

				if strings.Contains(lowerDesc, "hook_installed") || strings.Contains(lowerDesc, "hook installed") {
					severity = "medium" // hooking is generally interesting/warning
				}

				for _, keyword := range fridaInterestingKeywords {
					if strings.Contains(lowerDesc, keyword) {
						severity = "medium"
						break
					}
				}

				result.Findings = append(result.Findings, Finding{
					Source:      "frida",
					Severity:    severity,
					Title:       fmt.Sprintf("Frida: %s", eventType),
					Description: desc,
					RawData:     eMap,
					Service:     "mobile",
				})
			}
		}
	} else if logs, ok := resultMap["logs"].([]interface{}); ok {
		// Fallback to Old Schema (logs)
		for _, l := range logs {
			if logLine, ok := l.(string); ok {
				// Keyword matching for risk
				lowerLog := strings.ToLower(logLine)
				severity := "info"

				for _, keyword := range fridaInterestingKeywords {
					if strings.Contains(lowerLog, keyword) {
						severity = "medium"
						break
					}
				}

				result.Findings = append(result.Findings, Finding{
					Source:      "frida",
					Severity:    severity,
					Title:       "Frida Log",
					Description: logLine,
					RawData:     logLine,
					Service:     "mobile",
				})
			}
		}
	}

	return result, nil
}
