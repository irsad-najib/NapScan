package parser

import (
	"fmt"
)

type MobSFParser struct{}

func NewMobSFParser() *MobSFParser {
	return &MobSFParser{}
}

func (p *MobSFParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("mobsf result is not a map")
	}

	// Unwrap "mobsf" key if present (persistence wrapper)
	if inner, ok := resultMap["mobsf"].(map[string]interface{}); ok {
		resultMap = inner
	}

	// 1. Extract Score
	if score, ok := resultMap["security_score"].(float64); ok {
		// MobSF: 100 = aman, 0 = buruk
		// We just store it in metadata
		result.Metadata["security_score"] = score
	}
	if avgCVSS, ok := resultMap["average_cvss"].(float64); ok {
		result.Metadata["average_cvss"] = avgCVSS
	}

	// 2. Parse Findings (New Schema: findings are at root under "high", "warning", etc.)
	// Structure: { "findings": { "high": [...], "warning": [...], ... } }
	if findingsMap, ok := resultMap["findings"].(map[string]interface{}); ok {
		// Iterate over severity keys
		for sevKey, indList := range findingsMap {
			// standard keys: high, warning, info, secure, hotspot
			if findingsList, ok := indList.([]interface{}); ok {
				for _, fItem := range findingsList {
					if fMap, ok := fItem.(map[string]interface{}); ok {
						// Determine severity
						severity := "info"
						switch sevKey {
						case "high", "critical":
							severity = "high"
						case "warning":
							severity = "medium"
						case "secure":
							severity = "info"
						}

						// Extract details
						title := "MobSF Finding"
						if t, ok := fMap["title"].(string); ok {
							title = t
						}

						desc := ""
						if d, ok := fMap["description"].(string); ok {
							desc = d
						}

						fileLoc := ""
						if f, ok := fMap["file_path"].(string); ok {
							fileLoc = f
						}

						result.Findings = append(result.Findings, Finding{
							Source:      "mobsf",
							Severity:    severity,
							Title:       title,
							Description: desc,
							Target:      fileLoc,
							RawData:     fMap,
							Service:     "mobile",
						})
					}
				}
			}
		}
	} else if codeAnalysis, ok := resultMap["code_analysis"].(map[string]interface{}); ok {
		// Fallback to OLD Schema (code_analysis)
		if findings, ok := codeAnalysis["findings"].(map[string]interface{}); ok {
			for key, f := range findings {
				if fMap, ok := f.(map[string]interface{}); ok {
					// MobSF severity: warning, high, info
					severity := "info"
					if sev, ok := fMap["severity"].(string); ok {
						switch sev {
						case "high", "critical":
							severity = "high"
						case "warning":
							severity = "medium"
						}
					}

					title := key
					if metadata, ok := fMap["metadata"].(map[string]interface{}); ok {
						if desc, ok := metadata["description"].(string); ok {
							title = desc
						}
					}

					result.Findings = append(result.Findings, Finding{
						Source:      "mobsf",
						Severity:    severity,
						Title:       title,
						Description: fmt.Sprintf("Found in file: %v", key), // key is often filename
						RawData:     fMap,
						Target:      fmt.Sprintf("%v", key),
						Service:     "mobile",
					})
				}
			}
		}
	}

	// 3. Parse Permissions
	if permissions, ok := resultMap["permissions"].(map[string]interface{}); ok {
		dangerousCount := 0
		var dangerousPerms []string
		for permName, permData := range permissions {
			if pMap, ok := permData.(map[string]interface{}); ok {
				if status, ok := pMap["status"].(string); ok && status == "dangerous" {
					dangerousCount++
					dangerousPerms = append(dangerousPerms, permName)
				}
			}
		}
		if dangerousCount > 0 {
			result.Findings = append(result.Findings, Finding{
				Source:      "mobsf",
				Severity:    "medium",
				Title:       "Dangerous Permissions",
				Description: fmt.Sprintf("Found %d dangerous permissions: %v", dangerousCount, dangerousPerms),
				RawData:     permissions,
				Service:     "mobile",
				ReferenceID: "CWE-276", // Incorrect Default Permissions
			})
		}
	}

	return result, nil
}
