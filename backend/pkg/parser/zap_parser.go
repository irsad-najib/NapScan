package parser

import (
	"fmt"
	"strings"
)

type ZAPParser struct{}

func NewZAPParser() *ZAPParser {
	return &ZAPParser{}
}

func (p *ZAPParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("zap result is not a map")
	}

	// Wrapper check
	var alerts []interface{}

	if alertsRaw, ok := resultMap["alertsRaw"].(map[string]interface{}); ok {
		if a, ok := alertsRaw["alerts"].([]interface{}); ok {
			alerts = a
		}
	} else if _, ok := resultMap["site"].([]interface{}); ok {
		// XML JSON output sometimes has "site" array with "alerts" inside
		// ignoring deep nesting for now, strictly following previous logic
		// if "alertsRaw" structure is expected, we stick to it.
		// Use fallback if necessary.
	}

	// Fallback: check if "alerts" is direct key
	if len(alerts) == 0 {
		if a, ok := resultMap["alerts"].([]interface{}); ok {
			alerts = a
		}
	}

	if len(alerts) == 0 {
		return result, nil
	}

	for _, a := range alerts {
		alertMap, ok := a.(map[string]interface{})
		if !ok {
			continue
		}

		riskStr, _ := alertMap["risk"].(string)
		alertName, _ := alertMap["alert"].(string)
		url, _ := alertMap["url"].(string)
		method, _ := alertMap["method"].(string)
		desc, _ := alertMap["description"].(string)
		cweid, _ := alertMap["cweid"].(string)
		_, _ = alertMap["solution"].(string) // Ignore solution for now

		// Filter user agent fuzzer info
		if strings.Contains(strings.ToLower(alertName), "user agent fuzzer") &&
			strings.EqualFold(riskStr, "informational") {
			continue
		}

		// Map CWE if available
		refID := ""
		if cweid != "" && cweid != "-1" {
			refID = "CWE-" + cweid
		}

		result.Findings = append(result.Findings, Finding{
			Source:      "owasp-zap",
			Title:       alertName,
			Description: desc,
			Severity:    riskStr,
			Target:      url,
			Method:      method,
			ReferenceID: refID,
			RawData:     alertMap,
			Service:     "webapp",
		})
	}

	result.Metadata["total_findings"] = len(result.Findings)
	return result, nil
}
