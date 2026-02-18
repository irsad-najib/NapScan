package parser

import (
	"fmt"
)

type OpenVASParser struct{}

func NewOpenVASParser() *OpenVASParser {
	return &OpenVASParser{}
}

func (p *OpenVASParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("openvas result is not a map")
	}

	// Wrapper check
	var findings []interface{}

	if resultsContainer, ok := resultMap["results"].(map[string]interface{}); ok {
		if f, ok := resultsContainer["result"].([]interface{}); ok {
			findings = f
		}
	} else if f, ok := resultMap["result"].([]interface{}); ok {
		// Sometimes direct
		findings = f
	}

	if len(findings) == 0 {
		return result, nil
	}

	for _, finding := range findings {
		fMap, ok := finding.(map[string]interface{})
		if !ok {
			continue
		}

		// Fields often in OpenVAS: name, severity (score), threat (High/Medium/Low), host, port, nvts (cve, cwe)

		_ = getString(fMap, "severity") // "10.0" or similar, ignored for now
		name, _ := fMap["name"].(string)
		threat, _ := fMap["threat"].(string) // "High", "Medium"...
		hostMap, _ := fMap["host"].(map[string]interface{})
		host := ""
		if hostMap != nil {
			host, _ = hostMap["#text"].(string)
		}

		portMap, _ := fMap["port"].(map[string]interface{})
		port := ""
		if portMap != nil {
			port, _ = portMap["#text"].(string)
		}

		// Extract CVEs if available (often in nvt block)
		var refID string
		if nvt, ok := fMap["nvt"].(map[string]interface{}); ok {
			if cveWrap, ok := nvt["cve"].(map[string]interface{}); ok {
				// usually "CVE-2023-XXXX" in #text or similar, depends on parser
				if id, ok := cveWrap["#text"].(string); ok && id != "NOCVE" {
					refID = id
				}
			} else if cveStr, ok := nvt["cve"].(string); ok && cveStr != "NOCVE" {
				refID = cveStr
			}
		}

		description := name
		if threat != "" {
			description = fmt.Sprintf("%s [%s]", name, threat)
		}

		result.Findings = append(result.Findings, Finding{
			Source:      "openvas",
			Title:       name,
			Description: description,
			Severity:    threat, // Use threat level "High", "Medium" as severity
			Target:      fmt.Sprintf("%s:%s", host, port),
			ReferenceID: refID,
			RawData:     fMap,
			Service:     "infra",
		})
	}

	result.Metadata["total_findings"] = len(result.Findings)

	return result, nil
}

func getString(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}
