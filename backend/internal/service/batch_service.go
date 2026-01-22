// buatkan service untuk create batch id yang unik menggunakan uuid benerin biar routesnya nanti get
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/risk"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type BatchService struct {
	repo repository.BatchRepository
}

func NewBatchService(repo repository.BatchRepository) *BatchService {
	return &BatchService{repo: repo}
}

func (s *BatchService) CreateBatch(ctx context.Context, userID string) (string, error) {
	log.Printf("[BATCH_SERVICE] Creating batch for user_id=%s", userID)
	batchID := uuid.New().String()
	batch := &models.Batch{
		UserID:  userID,
		BatchID: batchID,
		Status:  models.BatchStatusProcessing,
	}
	err := s.repo.Create(ctx, batch)
	if err != nil {
		log.Printf("[BATCH_SERVICE] Failed to create batch: %v", err)
		return "", err
	}
	log.Printf("[BATCH_SERVICE] Database insert success for batch_id=%s", batchID)
	return batchID, nil
}

// ValidateBatchOwnership checks if a batch exists and belongs to the user.
func (s *BatchService) ValidateBatchOwnership(c *fiber.Ctx, batchID string) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[BATCH_SERVICE] Ownership check failed: user_id not found")
		return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
	}

	batch, err := s.repo.FindByID(c.Context(), batchID)
	if err != nil {
		log.Printf("[BATCH_SERVICE] Ownership check failed for batch_id=%s: %v", batchID, err)
		return fiber.NewError(fiber.StatusInternalServerError, "Could not verify batch ownership")
	}

	if batch == nil {
		log.Printf("[BATCH_SERVICE] Batch not found: batch_id=%s", batchID)
		return fiber.NewError(fiber.StatusNotFound, "Batch not found")
	}

	if batch.UserID != userID {
		log.Printf("[BATCH_SERVICE] Access denied: user=%s tried to access batch=%s owned by %s", userID, batchID, batch.UserID)
		return fiber.NewError(fiber.StatusForbidden, "You do not have permission to access this batch")
	}

	log.Printf("[BATCH_SERVICE] Ownership validated: user=%s batch=%s", userID, batchID)
	return nil
}

// calculateBatchRisk computes a risk score and returns detailed explanation
func (s *BatchService) calculateBatchRisk(batch *models.Batch) (int, interface{}) {
	maxRiskScore := 0.0
	var maxRiskResult interface{}
	var scanSummaries []string

	// Default Context (in future, this should come from Batch/Project settings)
	ctxFactors := risk.ContextFactors{
		AssetCriticality: "high",    // default to high safety
		Exposure:         "public",  // default to internet facing
		Environment:      "prod",    // default to production
	}

	checkRisk := func(severity string, sourceTool string, detail string) {
		log.Printf("[RISK_CALC] Checking severity: %s from %s", severity, sourceTool)
		scanSummaries = append(scanSummaries, fmt.Sprintf("%s: %s (%s)", sourceTool, detail, severity))
		// Map severity to representative CVSS vector
		var vector string
		switch severity {
		case "critical":
			vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" // Base ~10.0
		case "high":
			vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // Base ~8.8
		case "medium", "warning":
			vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" // Base ~5.3
		case "low":
			vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" // Base ~3.1
		default:
			log.Printf("[RISK_CALC] Unknown or safe severity: %s", severity)
			return
		}

		res, err := risk.CalculateRisk(risk.RiskInput{VectorString: vector}, ctxFactors)
		if err == nil {
			// Convert 0-10 scale to 0-100 for our API
			score100 := res.FinalScore * 10
			log.Printf("[RISK_CALC] Calculated score for %s: %.2f (Final: %.0f)", severity, res.FinalScore, score100)
			if score100 > maxRiskScore {
				maxRiskScore = score100
				maxRiskResult = res
			}
		} else {
			log.Printf("[RISK_CALC] Error calculating risk: %v", err)
		}
	}

	// 1. Check Uploaded Files
	log.Printf("[RISK_CALC] Checking %d uploaded files", len(batch.UploadedFiles))
	for _, file := range batch.UploadedFiles {
		checkRisk(file.Severity, "uploaded_file", file.FileName)
	}

	// 2. Check Scan Results
	log.Printf("[RISK_CALC] Checking %d scan results", len(batch.ScanResults))
	for _, result := range batch.ScanResults {
		scanSummaries = append(scanSummaries, fmt.Sprintf("Scanned with %s: Target %s", result.Tool, result.Target))
		
		if resMap, ok := result.Result.(map[string]interface{}); ok {
			
			// If tool gives risk_score directly (0-100), take it but maybe apply modifiers? 
			// For consistency, let's map it back to level if possible, or just use it raw.
			if toolScore, ok := resMap["risk_score"]; ok {
				log.Printf("[RISK_CALC] Found explicit tool risk_score: %v", toolScore)
				if sc, ok := toolScore.(float64); ok {
					scanSummaries = append(scanSummaries, fmt.Sprintf("%s: Found explicit risk score %v", result.Tool, sc))
					if sc > maxRiskScore { 
						maxRiskScore = sc 
						maxRiskResult = map[string]interface{}{
							"source": "tool_score",
							"tool": result.Tool,
							"score": sc,
						}
					}
				}
			}

			// Check Nmap open ports (Simple heuristic mapped to risk engine)
			if result.Tool == "nmap" {
				if hosts, ok := resMap["hosts"].([]interface{}); ok {
					for _, h := range hosts {
						if hostMap, ok := h.(map[string]interface{}); ok {
							if ports, ok := hostMap["ports"].([]interface{}); ok {
								scanSummaries = append(scanSummaries, fmt.Sprintf("Nmap: Discovered %d open ports", len(ports)))
								if len(ports) > 0 {
									log.Printf("[RISK_CALC] Found %d open ports in Nmap scan", len(ports))
									// Check for high risk ports (e.g., 21, 23, 445, 3389)
									isHighRiskPort := false
									var riskyPorts []string
									for _, p := range ports {
										if portMap, ok := p.(map[string]interface{}); ok {
											if portID, ok := portMap["portid"].(json.Number); ok {
												pid, _ := portID.Int64()
												if pid == 21 || pid == 23 || pid == 445 || pid == 3389 {
													isHighRiskPort = true
													riskyPorts = append(riskyPorts, fmt.Sprint(pid))
												}
											} else if portID, ok := portMap["portid"].(float64); ok { // Legacy float check
												pid := int(portID)
												if pid == 21 || pid == 23 || pid == 445 || pid == 3389 {
													isHighRiskPort = true
													riskyPorts = append(riskyPorts, fmt.Sprint(pid))
												}
											}
										}
									}
									if isHighRiskPort {
										checkRisk("high", "nmap_risky_ports", fmt.Sprintf("Risky ports open: %v", riskyPorts))
									} else {
										checkRisk("medium", "nmap_open_ports", fmt.Sprintf("%d ports open", len(ports)))
									}
								}
							}
						}
					}
				}
			}

			// Check SSLyze Results
			if result.Tool == "sslyze" {
				// SSLyze usually returns strict compliance errors in scanned structure
				// Check for deprecated protocols in "server_scan_results" -> "scan_commands_results"
				if serverResults, ok := resMap["server_scan_results"].([]interface{}); ok {
					for _, sr := range serverResults {
						if srMap, ok := sr.(map[string]interface{}); ok {
							if scanCmds, ok := srMap["scan_commands_results"].(map[string]interface{}); ok {
								// Check TLS 1.0 (High Risk)
								if tls10, ok := scanCmds["tls_1_0_cipher_suites"].(map[string]interface{}); ok {
									if accepted, ok := tls10["accepted_cipher_suites"].([]interface{}); ok && len(accepted) > 0 {
										checkRisk("high", "sslyze_tls1.0", "TLS 1.0 accepted")
									} else {
										scanSummaries = append(scanSummaries, "SSLyze: TLS 1.0 disabled (OK)")
									}
								}
								// Check SSL 2.0/3.0 (Critical Risk)
								if ssl20, ok := scanCmds["ssl_2_0_cipher_suites"].(map[string]interface{}); ok {
									if accepted, ok := ssl20["accepted_cipher_suites"].([]interface{}); ok && len(accepted) > 0 {
										checkRisk("critical", "sslyze_ssl2.0", "SSL 2.0/3.0 accepted")
									} else {
										scanSummaries = append(scanSummaries, "SSLyze: SSL 2.0/3.0 disabled (OK)")
									}
								}
							}
						}
					}
				}
			}

			// Check ZAP Results
			if result.Tool == "owasp-zap" {
				if alertsRaw, ok := resMap["alertsRaw"].(map[string]interface{}); ok {
					if alerts, ok := alertsRaw["alerts"].([]interface{}); ok {
						scanSummaries = append(scanSummaries, fmt.Sprintf("ZAP: Found %d alerts", len(alerts)))
						for _, a := range alerts {
							if alertMap, ok := a.(map[string]interface{}); ok {
								if riskStr, ok := alertMap["risk"].(string); ok {
									alertName, _ := alertMap["alert"].(string)
									// ZAP Risk: High, Medium, Low, Informational
									switch strings.ToLower(riskStr) {
									case "high":
										checkRisk("high", "zap_alert", alertName)
									case "medium":
										checkRisk("medium", "zap_alert", alertName)
									case "low":
										checkRisk("low", "zap_alert", alertName)
									}
								}
							}
						}
					} else {
						scanSummaries = append(scanSummaries, "ZAP: No alerts found")
					}
				}
			}

			// Check Nuclei Results
			if result.Tool == "nuclei" {
				// Nuclei Result is often a list of objects at the top level, 
				// BUT our ScanResult.Result handles it as interface{}. 
				// If it was stored as []interface{}, resMap check at top (line 121) would FAIL.
				// We need to handle []interface{} separately or check how GORM/Service saved it.
				// Service saves []map[string]interface{}. GORM -> generic JSON.
				// If 'resMap' is NOT valid, we might be in the 'else' block? 
				// Wait, line 121: `if resMap, ok := result.Result.(map[string]interface{}); ok`
				// Nuclei returns raw list `[]map[...]`. So line 121 might fail for Nuclei!
				// We need to check array type if map check fails.
			}
			
			// Check FFUF Results
			if result.Tool == "ffuf" {
				if results, ok := resMap["results"].([]interface{}); ok {
					scanSummaries = append(scanSummaries, fmt.Sprintf("FFUF: Found %d fuzzing matches", len(results)))
					for _, r := range results {
						if resObj, ok := r.(map[string]interface{}); ok {
							// Check status
							if status, ok := resObj["status"].(float64); ok { // JSON numbers are float64
								url, _ := resObj["url"].(string)
								if status == 200 {
									checkRisk("medium", "ffuf_found_200", url)
								} else if status == 403 {
									checkRisk("low", "ffuf_found_403", url)
								}
							}
						}
					}
				} else {
					scanSummaries = append(scanSummaries, "FFUF: No results")
				}
			}

			// Check OpenVAS Results
			if result.Tool == "openvas" {
				// OpenVAS structure: { "results": { "result": [ ... ] } }
				if resultsContainer, ok := resMap["results"].(map[string]interface{}); ok {
					if findings, ok := resultsContainer["result"].([]interface{}); ok {
						scanSummaries = append(scanSummaries, fmt.Sprintf("OpenVAS: Found %d findings", len(findings)))
						for _, finding := range findings {
							if fMap, ok := finding.(map[string]interface{}); ok {
								// Check Severity (String "4.8")
								if sevStr, ok := fMap["severity"].(string); ok {
									if sevVal, err := strconv.ParseFloat(sevStr, 64); err == nil {
										name := "Unknown Finding"
										if n, ok := fMap["name"].(string); ok {
											name = n
										}
										
										log.Printf("[RISK_CALC] OpenVAS Finding: %s (Sev: %f)", name, sevVal)
										
										// Calculate risk level from score
										var level string
										if sevVal >= 9.0 {
											level = "critical"
										} else if sevVal >= 7.0 {
											level = "high"
										} else if sevVal >= 4.0 {
											level = "medium"
										} else if sevVal > 0.0 {
											level = "low"
										} else {
											level = "info"
										}

										if level != "info" {
											checkRisk(level, "openvas_finding", name)
										} else {
											scanSummaries = append(scanSummaries, fmt.Sprintf("OpenVAS: Found info/log finding: %s", name))
										}

										// OpenVAS is 0-10. Our API needs 0-100.
										score100 := sevVal * 10
										if score100 > maxRiskScore {
											maxRiskScore = score100
											maxRiskResult = map[string]interface{}{
												"source": "openvas_finding",
												"name": name,
												"score": score100,
												"threat": fMap["threat"],
											}
										}
									}
								}
							}
						}
					}
				}
			}
		} else if resList, ok := result.Result.([]interface{}); ok {
			// Handle List-based results (e.g. Nuclei)
			if result.Tool == "nuclei" {
				scanSummaries = append(scanSummaries, fmt.Sprintf("Nuclei: Found %d findings", len(resList)))
				for _, item := range resList {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if info, ok := itemMap["info"].(map[string]interface{}); ok {
							if severity, ok := info["severity"].(string); ok {
								if name, ok := info["name"].(string); ok {
									checkRisk(strings.ToLower(severity), "nuclei_finding", name)
								} else {
									checkRisk(strings.ToLower(severity), "nuclei_finding", "unknown")
								}
							}
						}
					}
				}
			}
		} else {
			log.Printf("[RISK_CALC] Result for tool %s is not a valid map or list", result.Tool)
		}
	}
	
	// Prepare final response
	responseDetails := map[string]interface{}{
		"checks_performed": scanSummaries,
		"max_risk_result": maxRiskResult,
	}

	log.Printf("[RISK_CALC] Final calculated risk for batch %s: %d", batch.BatchID, int(maxRiskScore))
	// Return the combined details instead of just the max result
	return int(maxRiskScore), responseDetails
}

func (s *BatchService) GetUserBatches(ctx context.Context, userID string) ([]models.BatchSummaryResponse, error) {
	log.Printf("[BATCH_SERVICE] Fetching batches for user_id=%s", userID)
	batches, err := s.repo.FindBatchesByUserID(ctx, userID)
	if err != nil {
		log.Printf("[BATCH_SERVICE] Failed to fetch batches: %v", err)
		return nil, err
	}
	summaries := make([]models.BatchSummaryResponse, len(batches))
	for i, batch := range batches {
		var riskScore int
		// Try to get risk score from AnalysisResult if available
		if batch.AnalysisResult != nil {
			if arMap, ok := batch.AnalysisResult.(map[string]interface{}); ok {
				if rs, ok := arMap["risk_score"]; ok {
					if rsFloat, ok := rs.(float64); ok {
						riskScore = int(rsFloat)
					} else if rsInt, ok := rs.(int); ok {
						riskScore = rsInt
					}
				}
			}
		}

		// Calculate dynamically using Risk Engine if not set
		var riskDetails interface{}
		if riskScore == 0 {
			riskScore, riskDetails = s.calculateBatchRisk(batch)
		}

		// Get target: Check UploadedFiles first (APKs), then ScanResults (Network scans)
		target := "Unknown"
		if len(batch.UploadedFiles) > 0 {
			target = batch.UploadedFiles[0].FileName
		} else if len(batch.ScanResults) > 0 {
			target = batch.ScanResults[0].Target
		} else if batch.Status == models.BatchStatusProcessing {
			// If no relation yet, it's empty/unknown.
			target = "Scanning..." 
		}

		// Infer status: Logic to determine if batch is truly complete
		status := string(batch.Status)
		
		// 1. Check Uploaded Files (APKs)
		if len(batch.UploadedFiles) > 0 {
			allDone := true
			for _, f := range batch.UploadedFiles {
				// If any file is NOT in a terminal state, the batch is still processing
				if f.Status != models.FileStatusCompleted && 
				   f.Status != models.FileStatusFailed && 
				   f.Status != models.FileStatusCleaned {
					allDone = false
					break
				}
			}
			if allDone {
				status = "complete"
			} else {
				status = "processing"
			}
		} else if len(batch.ScanResults) > 0 {
			// 2. Check Network Scans
			// If we have results (and no files), assume complete (since we don't track expected count yet)
			if status == "processing" {
				status = "complete"
			}
		}

		summaries[i] = models.BatchSummaryResponse{
			BatchID:     batch.BatchID,
			Target:      target,
			RiskScore:   riskScore,
			RiskDetails: riskDetails,
			Status:      status,
			Timestamp:   batch.CreatedAt,
		}
	}
	
	log.Printf("[BATCH_SERVICE] Found %d batches", len(batches))
	return summaries, nil
}