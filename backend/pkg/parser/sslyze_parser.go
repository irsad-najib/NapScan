package parser

import (
	"fmt"
	"napscan-be/internal/models"
	"sort"
	"strings"
)

type SSLyzeParser struct{}

func NewSSLyzeParser() *SSLyzeParser {
	return &SSLyzeParser{}
}

var sslyzeRiskMap = map[string]int{
	"ssl2": 95,
	"ssl3": 95,
	"tls1.0": 80,
	"tls1.1": 60,
	"weak_cipher": 65,
}

func (p *SSLyzeParser) Parse(rawResult interface{}) (*ParsedResult, error) {
	highestRisk := 0
	result := &ParsedResult{
		Findings: []Finding{},
		Metadata: make(map[string]interface{}),
	}

	resultMap, ok := rawResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("sslyze result is not a map")
	}

	serverResults, ok := resultMap["server_scan_results"].([]interface{})
	if !ok {
		return result, nil
	}

	for _, sr := range serverResults {
		srMap, ok := sr.(map[string]interface{})
		if !ok {
			continue
		}

		scanCmds, ok := srMap["scan_commands_results"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check for SSL 2.0/3.0 (CRITICAL)
		if ssl20, ok := scanCmds["ssl_2_0_cipher_suites"].(map[string]interface{}); ok {
			if accepted, ok := ssl20["accepted_cipher_suites"].([]interface{}); ok && len(accepted) > 0 {
				result.Findings = append(result.Findings, Finding{
					Severity:    "info",
					Title:       "SSL 2.0/3.0 Enabled",
					Description: "SSL 2.0/3.0 accepted (deprecated and insecure)",
					RawData:     accepted,
				})
				if sslyzeRiskMap["ssl2"] > highestRisk {
					highestRisk = sslyzeRiskMap["ssl2"]
				}
			}
		}

		// Check for TLS 1.0 (HIGH)
		if tls10, ok := scanCmds["tls_1_0_cipher_suites"].(map[string]interface{}); ok {
			if accepted, ok := tls10["accepted_cipher_suites"].([]interface{}); ok && len(accepted) > 0 {
				result.Findings = append(result.Findings, Finding{
					Severity:    "high",
					Title:       "TLS 1.0 Enabled",
					Description: "TLS 1.0 enabled (deprecated)",
					RawData:     accepted,
				})
				if sslyzeRiskMap["tls1.0"] > highestRisk {
					highestRisk = sslyzeRiskMap["tls1.0"]
				}
			}
		}

		// Check for TLS 1.1 (MEDIUM)
		if tls11, ok := scanCmds["tls_1_1_cipher_suites"].(map[string]interface{}); ok {
			if accepted, ok := tls11["accepted_cipher_suites"].([]interface{}); ok && len(accepted) > 0 {
				result.Findings = append(result.Findings, Finding{
					Severity:    "medium",
					Title:       "TLS 1.1 Enabled",
					Description: "TLS 1.1 enabled (should upgrade to TLS 1.2+)",
					RawData:     accepted,
				})
				if sslyzeRiskMap["tls1.1"] > highestRisk {
					highestRisk = sslyzeRiskMap["tls1.1"]
				}
			}
		}

		// Check for weak ciphers in TLS 1.2
		if tls12, ok := scanCmds["tls_1_2_cipher_suites"].(map[string]interface{}); ok {
			if accepted, ok := tls12["accepted_cipher_suites"].([]interface{}); ok {
				for _, cipher := range accepted {
					if cipherMap, ok := cipher.(map[string]interface{}); ok {
						if cipherName, ok := cipherMap["cipher_suite"].(map[string]interface{}); ok {
							if name, ok := cipherName["name"].(string); ok {
								if isWeakCipher(name) {
									result.Findings = append(result.Findings, Finding{
										Severity:    "medium",
										Title:       "Weak Cipher Suite",
										Description: fmt.Sprintf("Weak cipher suite: %s", name),
										RawData:     cipherMap,
									})
									if sslyzeRiskMap["weak_cipher"] > highestRisk {
										highestRisk = sslyzeRiskMap["weak_cipher"]
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, Finding{
			Severity:    "info",
			Title:       "SSL/TLS Configuration OK",
			Description: "No major SSL/TLS configuration issues detected",
			RawData:     nil,
		})
	}

	result.Metadata["highest_risk"] = highestRisk

	return result, nil
}

func (p *SSLyzeParser) Normalize(parsed *ParsedResult) (*models.ScannerRiskDetail, error) {
	detail := &models.ScannerRiskDetail{
		Scanner:  "sslyze",
		Findings: []string{},
	}

	highestRisk := 0
	if v, ok := parsed.Metadata["highest_risk"].(int); ok {
		highestRisk = v
	}

	var allFindings []string
	for _, finding := range parsed.Findings {
		allFindings = append(allFindings, finding.Description)
	}

	finalSeverity := models.SeverityInfo
	switch {
	case highestRisk >= 90:
		finalSeverity = models.SeverityCritical
	case highestRisk >= 75:
		finalSeverity = models.SeverityHigh
	case highestRisk >= 50:
		finalSeverity = models.SeverityMedium
	case highestRisk >= 30:
		finalSeverity = models.SeverityLow
	}

	detail.NormalizedSeverity = finalSeverity
	detail.Description = "SSL/TLS configuration weaknesses identified"

	sort.Strings(allFindings)
	detail.Findings = allFindings

	findingCount := float64(len(allFindings))
	if findingCount == 0 {
		findingCount = 1
	}

	detail.Score = float64(highestRisk)*10 + findingCount*2
	return detail, nil
}

func (p *SSLyzeParser) ParseAndNormalize(rawResults []models.ScanResult) (*models.ScannerRiskDetail, error) {
	aggregatedFindings := []string{}
	highestSeverity := models.SeverityInfo

	for _, scanResult := range rawResults {
		parsed, err := p.Parse(scanResult.Result)
		if err != nil {
			continue
		}

		normalized, err := p.Normalize(parsed)
		if err != nil {
			continue
		}

		if models.GetSeverityScore(normalized.NormalizedSeverity) > models.GetSeverityScore(highestSeverity) {
			highestSeverity = normalized.NormalizedSeverity
		}

		aggregatedFindings = append(aggregatedFindings, normalized.Findings...)
	}

	uniqueFindings := removeDuplicates(aggregatedFindings)
	sort.Strings(uniqueFindings)

	detail := &models.ScannerRiskDetail{
		Scanner:            "sslyze",
		NormalizedSeverity: highestSeverity,
		Description:        "SSL/TLS configuration weaknesses identified",
		Findings:           uniqueFindings,
	}

	baseScore := models.GetSeverityScore(highestSeverity)
	findingCount := float64(len(uniqueFindings))
	if findingCount == 0 {
		findingCount = 1
	}
	detail.Score = baseScore * findingCount

	return detail, nil
}

// Helper function to identify weak ciphers
func isWeakCipher(cipherName string) bool {
	weak := []string{"3DES", "RC4", "MD5", "NULL", "EXPORT", "anon"}
	for _, w := range weak {
		if strings.Contains(strings.ToUpper(cipherName), w) {
			return true
		}
	}
	return false
}

