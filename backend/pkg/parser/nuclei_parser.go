package parser

import (
	"fmt"
)

type NucleiParser struct{}

func NewNucleiParser() *NucleiParser {
	return &NucleiParser{}
}

func (p *NucleiParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	// Nuclei returns an array of findings, but sometimes might be a single map (e.g. single JSONL line)
	var resList []interface{}

	if asMap, ok := rawResult.(map[string]interface{}); ok {
		resList = []interface{}{asMap}
	} else if asList, ok := rawResult.([]interface{}); ok {
		resList = asList
	} else {
		return nil, fmt.Errorf("nuclei result is not an array or map")
	}

	for _, item := range resList {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		info, ok := itemMap["info"].(map[string]interface{})
		if !ok {
			continue
		}

		category, _ := info["category"].(string)

		severity, _ := info["severity"].(string)
		name, _ := info["name"].(string)
		matchedAt, _ := itemMap["matched-at"].(string)

		// Extract CVE/CWE
		var refID string

		if classification, ok := info["classification"].(map[string]interface{}); ok {
			// Try CVE
			if cves, ok := classification["cve-id"]; ok {
				if s, ok := cves.(string); ok && s != "" {
					refID = s
				} else if list, ok := cves.([]interface{}); ok && len(list) > 0 {
					if s, ok := list[0].(string); ok {
						refID = s
					}
				}
			}
			// Try CWE if no CVE
			if refID == "" {
				if cwes, ok := classification["cwe-id"]; ok {
					if s, ok := cwes.(string); ok && s != "" {
						refID = s
					} else if list, ok := cwes.([]interface{}); ok && len(list) > 0 {
						if s, ok := list[0].(string); ok {
							refID = s
						}
					}
				}
			}
		}

		finding := Finding{
			Source:      "nuclei",
			Title:       name,
			Description: fmt.Sprintf("%s [%s] on %s", name, category, matchedAt),
			Severity:    severity,
			Target:      matchedAt,
			ReferenceID: refID,    // CVE or CWE
			Service:     category, // exposed-panels, etc can serve as service category
			RawData:     itemMap,
		}

		result.Findings = append(result.Findings, finding)
	}

	result.Metadata["total_findings"] = len(result.Findings)

	return result, nil
}
