package parser

import (
	"fmt"
	"strings"
)

type SSLyzeParser struct{}

func NewSSLyzeParser() *SSLyzeParser {
	return &SSLyzeParser{}
}

func (p *SSLyzeParser) Parse(rawResult interface{}) (*ParsedResult, error) {
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
					Source:      "sslyze",
					Severity:    "critical",
					Title:       "SSL 2.0/3.0 Enabled",
					Description: "SSL 2.0/3.0 accepted (deprecated and insecure)",
					RawData:     accepted,
					Service:     "ssl",
					ReferenceID: "CWE-326", // Inadequate Encryption Strength
				})
			}
		}

		// Check for TLS 1.0 (HIGH)
		if tls10, ok := scanCmds["tls_1_0_cipher_suites"].(map[string]interface{}); ok {
			if accepted, ok := tls10["accepted_cipher_suites"].([]interface{}); ok && len(accepted) > 0 {
				result.Findings = append(result.Findings, Finding{
					Source:      "sslyze",
					Severity:    "high",
					Title:       "TLS 1.0 Enabled",
					Description: "TLS 1.0 enabled (deprecated)",
					RawData:     accepted,
					Service:     "ssl",
					ReferenceID: "CWE-326",
				})
			}
		}

		// Check for TLS 1.1 (MEDIUM)
		if tls11, ok := scanCmds["tls_1_1_cipher_suites"].(map[string]interface{}); ok {
			if accepted, ok := tls11["accepted_cipher_suites"].([]interface{}); ok && len(accepted) > 0 {
				result.Findings = append(result.Findings, Finding{
					Source:      "sslyze",
					Severity:    "medium",
					Title:       "TLS 1.1 Enabled",
					Description: "TLS 1.1 enabled (should upgrade to TLS 1.2+)",
					RawData:     accepted,
					Service:     "ssl",
					ReferenceID: "CWE-326",
				})
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
										Source:      "sslyze",
										Severity:    "medium",
										Title:       "Weak Cipher Suite",
										Description: fmt.Sprintf("Weak cipher suite: %s", name),
										RawData:     cipherMap,
										Service:     "ssl",
										ReferenceID: "CWE-327", // Broken or Risky Crypto
									})
								}
							}
						}
					}
				}
			}
		}
	}

	return result, nil
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
