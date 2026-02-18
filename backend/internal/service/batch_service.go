// buatkan service untuk create batch id yang unik menggunakan uuid benerin biar routesnya nanti get
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"strconv"
	"strings"

	"napscan-be/pkg/logger"
	"napscan-be/pkg/risk"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type BatchService struct {
	repo        repository.BatchRepository
	scanRepo    repository.ScanResultRepository
	findingRepo repository.FindingRepository
	riskService *RiskService
}

func NewBatchService(repo repository.BatchRepository, scanRepo repository.ScanResultRepository, findingRepo repository.FindingRepository, riskService *RiskService) *BatchService {
	return &BatchService{
		repo:        repo,
		scanRepo:    scanRepo,
		findingRepo: findingRepo,
		riskService: riskService,
	}
}

func (s *BatchService) CreateBatch(ctx context.Context, userID string) (string, error) {
	logger.Info("[BATCH_SERVICE] Creating batch for user_id=%s", userID)
	batchID := uuid.New().String()
	batch := &models.Batch{
		UserID:  userID,
		BatchID: batchID,
		Status:  models.BatchStatusProcessing,
	}
	err := s.repo.Create(ctx, batch)
	if err != nil {
		logger.Error("[BATCH_SERVICE] Failed to create batch: %v", err)
		return "", err
	}
	logger.Info("[BATCH_SERVICE] Database insert success for batch_id=%s", batchID)
	return batchID, nil
}

// ValidateBatchOwnership checks if a batch exists and belongs to the user.
func (s *BatchService) ValidateBatchOwnership(c *fiber.Ctx, batchID string) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		logger.Warn("[BATCH_SERVICE] Ownership check failed: user_id not found")
		return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
	}

	batch, err := s.repo.FindByID(c.Context(), batchID)
	if err != nil {
		logger.Error("[BATCH_SERVICE] Ownership check failed for batch_id=%s: %v", batchID, err)
		return fiber.NewError(fiber.StatusInternalServerError, "Could not verify batch ownership")
	}

	if batch == nil {
		logger.Warn("[BATCH_SERVICE] Batch not found: batch_id=%s", batchID)
		return fiber.NewError(fiber.StatusNotFound, "Batch not found")
	}

	if batch.UserID != userID {
		logger.Warn("[BATCH_SERVICE] Access denied: user=%s tried to access batch=%s owned by %s", userID, batchID, batch.UserID)
		return fiber.NewError(fiber.StatusForbidden, "You do not have permission to access this batch")
	}

	logger.Info("[BATCH_SERVICE] Ownership validated: user=%s batch=%s", userID, batchID)
	return nil
}

// DeleteBatch deletes a batch if owned by the user
func (s *BatchService) DeleteBatch(ctx context.Context, batchID, userID string) error {
	logger.Info("[BATCH_SERVICE] Deleting batch_id=%s for user_id=%s", batchID, userID)

	// Verify ownership first
	// Note: ValidateBatchOwnership takes *fiber.Ctx which we don't have here directly,
	// so we'll do manual check similar to GetBatchDetail
	batch, err := s.repo.FindByID(ctx, batchID)
	if err != nil {
		return err
	}
	if batch == nil {
		return fmt.Errorf("batch not found")
	}
	if batch.UserID != userID {
		return fmt.Errorf("access denied")
	}

	// Delete
	if err := s.repo.Delete(ctx, batchID); err != nil {
		logger.Error("[BATCH_SERVICE] Failed to delete batch: %v", err)
		return err
	}

	logger.Info("[BATCH_SERVICE] Batch deleted successfully")
	return nil
}

// calculateBatchRisk computes a risk score and returns detailed explanation
func (s *BatchService) calculateBatchRisk(batch *models.Batch) (int, interface{}) {
	maxRiskScore := 0.0
	var maxRiskResult interface{}
	var scanSummaries []string

	// Default Context (in future, this should come from Batch/Project settings)
	// ctxFactors := risk.ContextFactors{
	// 	AssetCriticality: "high",    // default to high safety
	// 	Exposure:         "public",  // default to internet facing
	// 	Environment:      "prod",    // default to production
	// }

	checkRisk := func(severity string, sourceTool string, detail string) {
		logger.Info("[RISK_CALC] Checking severity: %s from %s", severity, sourceTool)
		scanSummaries = append(scanSummaries, fmt.Sprintf("%s: %s (%s)", sourceTool, detail, severity))
		// Map severity to representative CVSS vector
		// var vector string
		// switch severity {
		// case "critical":
		// 	vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" // Base ~10.0
		// case "high":
		// 	vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // Base ~8.8
		// case "medium", "warning":
		// 	vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" // Base ~5.3
		// case "low":
		// 	vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" // Base ~3.1
		// default:
		// 	log.Printf("[RISK_CALC] Unknown or safe severity: %s", severity)
		// 	return
		// }

		// res, err := risk.CalculateRisk(risk.RiskInput{VectorString: vector}, ctxFactors)
		// if err == nil {
		// 	// Convert 0-10 scale to 0-100 for our API
		// 	score100 := res.FinalScore * 10
		// 	log.Printf("[RISK_CALC] Calculated score for %s: %.2f (Final: %.0f)", severity, res.FinalScore, score100)
		// 	if score100 > maxRiskScore {
		// 		maxRiskScore = score100
		// 		maxRiskResult = res
		// 	}
		// } else {
		// 	log.Printf("[RISK_CALC] Error calculating risk: %v", err)
		// }
	}

	// 1. Check Uploaded Files
	logger.Info("[RISK_CALC] Checking %d uploaded files", len(batch.UploadedFiles))
	for _, file := range batch.UploadedFiles {
		checkRisk(file.Severity, "uploaded_file", file.FileName)
	}

	// 2. Check Scan Results
	logger.Info("[RISK_CALC] Checking %d scan results", len(batch.ScanResults))
	for _, result := range batch.ScanResults {
		scanSummaries = append(scanSummaries, fmt.Sprintf("Scanned with %s: Target %s", result.Tool, result.Target))

		var resMap map[string]interface{}
		// Manually parse ResultRaw if Result is nil
		if result.Result == nil && len(result.ResultRaw) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(result.ResultRaw))
			decoder.UseNumber()
			_ = decoder.Decode(&resMap) // Ignore error, best effort
		} else if m, ok := result.Result.(map[string]interface{}); ok {
			resMap = m
		}

		if resMap != nil {

			// If tool gives risk_score directly (0-100), take it but maybe apply modifiers?
			// For consistency, let's map it back to level if possible, or just use it raw.
			if toolScore, ok := resMap["risk_score"]; ok {
				logger.Info("[RISK_CALC] Found explicit tool risk_score: %v", toolScore)
				if sc, ok := toolScore.(float64); ok {
					scanSummaries = append(scanSummaries, fmt.Sprintf("%s: Found explicit risk score %v", result.Tool, sc))
					if sc > maxRiskScore {
						maxRiskScore = sc
						maxRiskResult = map[string]interface{}{
							"source": "tool_score",
							"tool":   result.Tool,
							"score":  sc,
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
									logger.Info("[RISK_CALC] Found %d open ports in Nmap scan", len(ports))
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
								switch status {
								case 200:
									checkRisk("medium", "ffuf_found_200", url)
								case 403:
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

										logger.Info("[RISK_CALC] OpenVAS Finding: %s (Sev: %f)", name, sevVal)

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
												"name":   name,
												"score":  score100,
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
		} else {
			// Handle List-based results (e.g. Nuclei)
			// Check if we can parse as list
			var resList []interface{}
			if result.Result == nil && len(result.ResultRaw) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(result.ResultRaw))
				decoder.UseNumber()
				_ = decoder.Decode(&resList)
			} else if list, ok := result.Result.([]interface{}); ok {
				resList = list
			}

			if resList != nil && result.Tool == "nuclei" {
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
			if resList == nil {
				logger.Info("[RISK_CALC] Result for tool %s is not a valid map or list", result.Tool)
			}
		}
	}

	// Prepare final response
	responseDetails := map[string]interface{}{
		"checks_performed": scanSummaries,
		"max_risk_result":  maxRiskResult,
	}

	logger.Info("[RISK_CALC] Final calculated risk for batch %s: %d", batch.BatchID, int(maxRiskScore))
	// Return the combined details instead of just the max result
	return int(maxRiskScore), responseDetails
}

func (s *BatchService) GetUserBatches(ctx context.Context, userID string) ([]models.BatchSummaryResponse, error) {
	logger.Info("[BATCH_SERVICE] Fetching batches for user_id=%s", userID)
	batches, err := s.repo.FindBatchesByUserID(ctx, userID)
	if err != nil {
		logger.Error("[BATCH_SERVICE] Failed to fetch batches: %v", err)
		return nil, err
	}
	summaries := make([]models.BatchSummaryResponse, len(batches))
	for i, batch := range batches {
		var riskScore int
		// Try to get risk score from AnalysisResult if available
		if batch.AnalysisResult == nil && len(batch.AnalysisResultRaw) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(batch.AnalysisResultRaw))
			decoder.UseNumber()
			_ = decoder.Decode(&batch.AnalysisResult)
		}

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
			// Use the new Normalized Risk Engine (Internal Helper avoiding DB calls if possible)
			// effectively using the preloaded results
			riskResp, err := s.calculateNormalizedRiskInternal(batch.BatchID, batch.ScanResults)
			if err == nil {
				riskScore = int(riskResp.RiskScore)
				// We can optionally attach details, but for summary, maybe just score is enough?
				// The original code passed 'riskDetails'.
				riskDetails = riskResp.RiskDetail
			} else {
				// Fallback to old method or just 0?
				// User explicitly asked for "correct calculation by batch id"
				// old method: score, details := s.calculateBatchRisk(batch)
				// Let's rely on the new one.
				logger.Warn("[BATCH_SERVICE] Failed to calculate normalized risk for batch %s: %v", batch.BatchID, err)
			}
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
			Timestamp:   batch.CreatedAt, // ensure CreatedAt is available on batch model
		}
	}

	logger.Info("[BATCH_SERVICE] Found %d batches", len(batches))
	return summaries, nil
}

// CalculateBatchRiskNormalized calculates risk using the new normalized risk engine
func (s *BatchService) CalculateBatchRiskNormalized(ctx context.Context, batchID string) (*models.BatchRiskResponse, error) {
	logger.Info("[BATCH_SERVICE] Calculating normalized risk for batch_id=%s", batchID)

	// 1. Fetch all scan results for this batch
	scanResults, err := s.scanRepo.FindByBatchID(ctx, batchID)
	if err != nil {
		logger.Error("[BATCH_SERVICE] Failed to fetch scan results: %v", err)
		return nil, err
	}

	return s.calculateNormalizedRiskInternal(batchID, scanResults)
}

// calculateNormalizedRiskInternal contains the core logic for risk calculation given a set of scan results
func (s *BatchService) calculateNormalizedRiskInternal(batchID string, scanResults []models.ScanResult) (*models.BatchRiskResponse, error) {
	logger.Info("[BATCH_SERVICE] Found %d scan results for batch", len(scanResults))

	// 2. Group scan results by scanner type
	scannerGroups := make(map[string][]models.ScanResult)
	for _, result := range scanResults {
		// Populate Result from ResultRaw so parsers (which expect Result) work
		if result.Result == nil && len(result.ResultRaw) > 0 {
			// Used by parsers (mobsf, zap, etc). Most expect map[string]interface{} OR []interface{}
			// We try to decode into interface{}
			var temp interface{}
			decoder := json.NewDecoder(bytes.NewReader(result.ResultRaw))
			decoder.UseNumber()
			if err := decoder.Decode(&temp); err == nil {
				result.Result = temp
			} else {
				logger.Warn("[BATCH_SERVICE] Failed to decode raw result for parser: %v", err)
			}
		}
		scannerGroups[result.Tool] = append(scannerGroups[result.Tool], result)
	}

	logger.Info("[BATCH_SERVICE] Grouped into %d scanner types", len(scannerGroups))

	// 3. Parse and normalize each scanner group
	var scannerDetails []models.ScannerRiskDetail
	for scannerType, results := range scannerGroups {
		logger.Info("[BATCH_SERVICE] Processing scanner: %s with %d results", scannerType, len(results))

		// Try to fetch from DetectedFindings first (Persisted Intelligence)
		storedFindings, err := s.findingRepo.GetByBatchIDAndTool(context.Background(), batchID, scannerType)
		if err == nil && len(storedFindings) > 0 {
			logger.Info("[BATCH_SERVICE] Found %d persisted findings for %s", len(storedFindings), scannerType)

			normalizedFindings := []string{}
			highestSeverity := models.SeverityInfo

			for _, f := range storedFindings {
				// Use persisted finding data
				normalizedFindings = append(normalizedFindings, fmt.Sprintf("%s: %s", f.Title, f.Description))

				// Calculate max severity
				norm := models.NormalizeSeverity(f.Severity)
				if models.GetSeverityScore(norm) > models.GetSeverityScore(highestSeverity) {
					highestSeverity = norm
				}
			}

			detail := models.ScannerRiskDetail{
				Scanner:            scannerType,
				NormalizedSeverity: highestSeverity,
				Findings:           normalizedFindings,
				Score:              models.GetSeverityScore(highestSeverity) * 10,
			}
			scannerDetails = append(scannerDetails, detail)
			continue
		}

		// Fallback: Parse raw result if no findings in DB
		parser := risk.GetParser(scannerType)
		if parser == nil {
			logger.Warn("[BATCH_SERVICE] No parser found for scanner: %s", scannerType)
			continue
		}

		// (Logic for finding raw result in 'results' slice)
		// Usually results has multiple ScanResults if chunked, but most tools have 1 ScanResult per tool per batch
		// except maybe if parallel tasks ran? Scheduler runs 1 task per tool per schedule.
		// So results[0] should be enough?
		// But let's combine if multiple.

		// For simplicity, we just parse the first non-empty result for now in fallback mode.
		// Or creating a merged raw result.

		if len(results) == 0 {
			continue
		}

		// Use the first result's Result/ResultRaw
		res := results[0]

		// Decode raw result
		var resultInterface interface{}
		if res.Result != nil {
			resultInterface = res.Result
		} else if len(res.ResultRaw) > 0 {
			var temp interface{}
			dec := json.NewDecoder(bytes.NewReader(res.ResultRaw))
			dec.UseNumber()
			if err := dec.Decode(&temp); err == nil {
				resultInterface = temp
			}
		}

		parsed, err := parser.Parse(resultInterface)
		if err != nil {
			logger.Error("[BATCH_SERVICE] Failed to parse %s results: %v", scannerType, err)
			continue
		}

		// Normalize findings manually since ParseAndNormalize is removed
		normalizedFindings := []string{}
		highestSeverity := models.SeverityInfo

		for _, finding := range parsed.Findings {
			// Append description/title to findings list
			normalizedFindings = append(normalizedFindings, fmt.Sprintf("%s: %s", finding.Title, finding.Description))

			// Check severity
			rawSev := finding.Severity
			norm := models.NormalizeSeverity(rawSev)
			if models.GetSeverityScore(norm) > models.GetSeverityScore(highestSeverity) {
				highestSeverity = norm
			}
		}

		detail := models.ScannerRiskDetail{
			Scanner:            scannerType,
			NormalizedSeverity: highestSeverity,
			Findings:           normalizedFindings,
			Score:              models.GetSeverityScore(highestSeverity) * 10, // Rough estimate
		}

		scannerDetails = append(scannerDetails, detail)
	}

	// 4. Calculate batch risk
	riskResponse := risk.CalculateBatchRisk(batchID, scannerDetails)

	logger.Info("[BATCH_SERVICE] Calculated risk: score=%.2f, level=%s, scanners=%d",
		riskResponse.RiskScore, riskResponse.RiskLevel, len(riskResponse.RiskDetail))

	return riskResponse, nil
}

// GetBatchDetail retrieves complete batch information including normalized risk
func (s *BatchService) GetBatchDetail(ctx context.Context, batchID string, userID string) (*models.BatchDetailResponse, error) {
	logger.Info("[BATCH_SERVICE] Fetching batch detail for batch_id=%s, user_id=%s", batchID, userID)

	// 1. Fetch batch
	batch, err := s.repo.FindByID(ctx, batchID)
	if err != nil {
		logger.Error("[BATCH_SERVICE] Failed to fetch batch: %v", err)
		return nil, err
	}

	if batch == nil {
		logger.Warn("[BATCH_SERVICE] Batch not found: %s", batchID)
		return nil, fmt.Errorf("batch not found")
	}

	// 2. Verify ownership
	if batch.UserID != userID {
		logger.Warn("[BATCH_SERVICE] Access denied: user=%s tried to access batch owned by %s", userID, batch.UserID)
		return nil, fmt.Errorf("access denied")
	}

	// 3. Fetch scan results
	scanResults, err := s.scanRepo.FindByBatchID(ctx, batchID)
	if err != nil {
		logger.Error("[BATCH_SERVICE] Failed to fetch scan results: %v", err)
		return nil, err
	}

	// 4. Calculate normalized risk
	riskResponse, err := s.CalculateBatchRiskNormalized(ctx, batchID)
	if err != nil {
		logger.Warn("[BATCH_SERVICE] Failed to calculate risk: %v", err)
		// Continue with zero risk if calculation fails
		riskResponse = &models.BatchRiskResponse{
			BatchID:    batchID,
			RiskScore:  0,
			RiskLevel:  models.SeverityInfo,
			RiskDetail: []models.ScannerRiskDetail{},
		}
	}
	if riskResponse.RiskDetail == nil {
		riskResponse.RiskDetail = []models.ScannerRiskDetail{}
	}

	// 5. Determine target
	target := "Unknown"
	if len(batch.UploadedFiles) > 0 {
		target = batch.UploadedFiles[0].FileName
	} else if len(scanResults) > 0 {
		target = scanResults[0].Target
	}

	// 6. Determine status
	status := string(batch.Status)
	if len(batch.UploadedFiles) > 0 {
		allDone := true
		for _, f := range batch.UploadedFiles {
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
	} else if len(scanResults) > 0 {
		if status == "processing" {
			status = "complete"
		}
	}

	// 7. Build response
	scanSummaries := make([]models.ScanResultSummary, 0)
	for _, res := range scanResults {
		scanSummaries = append(scanSummaries, s.summarizeScanResult(res))
	}
	// log.Printf("[DEBUG] UploadedFiles len = %d", len(batch.UploadedFiles))
	// log.Printf("[DEBUG] ScanResults len = %d", len(scanResults))

	// // ---- STEP 1: Mobile scans (MobSF / Frida) ----
	// if len(batch.UploadedFiles) > 0 {

	// 	file := batch.UploadedFiles[0] // asumsi 1 APK per batch

	// 	scanSummaries = append(
	// 		scanSummaries,
	// 		s.summarizeMobileScan(batch, "mobsf", file.FileName),
	// 	)

	// 	scanSummaries = append(
	// 		scanSummaries,
	// 		s.summarizeMobileScan(batch, "frida", file.FileName),
	// 	)
	// }

	response := &models.BatchDetailResponse{
		BatchID:     batch.BatchID,
		UserID:      batch.UserID,
		Status:      status,
		CreatedAt:   batch.CreatedAt,
		Target:      target,
		RiskScore:   riskResponse.RiskScore,
		RiskLevel:   riskResponse.RiskLevel,
		RiskDetail:  riskResponse.RiskDetail,
		ScanResults: scanSummaries,
	}

	logger.Info("[BATCH_SERVICE] Batch detail prepared: status=%s, risk_score=%.2f", status, riskResponse.RiskScore)

	return response, nil
}

// summarizeScanResult transforms raw scan results into a simplified summary
func (s *BatchService) summarizeScanResult(scan models.ScanResult) models.ScanResultSummary {
	summary := models.ScanResultSummary{
		ID:        scan.ID,
		Tool:      scan.Tool,
		Target:    scan.Target,
		CreatedAt: scan.CreatedAt,
		Result:    scan.ResultRaw, // Pass through raw JSON directly
	}

	// Helper to get interface{} map/slice from raw
	var resultInterface interface{}
	if scan.Result != nil {
		resultInterface = scan.Result
	} else if len(scan.ResultRaw) > 0 {
		var temp interface{}
		decoder := json.NewDecoder(bytes.NewReader(scan.ResultRaw))
		decoder.UseNumber()
		if err := decoder.Decode(&temp); err == nil {
			resultInterface = temp
		}
	}

	// Canonicalize tool name (handle aliases)
	toolName := strings.ToLower(scan.Tool)
	if toolName == "zap" {
		toolName = "owasp-zap"
	}

	summary.Tool = toolName // Normalize in output too

	switch toolName {
	case "mobsf":
		summary.Summary = map[string]interface{}{
			"info": "See detailed report for more info",
		}
		if resMap, ok := resultInterface.(map[string]interface{}); ok {
			// Unwrap if nested
			if inner, ok := resMap["mobsf"].(map[string]interface{}); ok {
				resMap = inner
			}
			if score, ok := resMap["security_score"]; ok {
				summary.Summary = map[string]interface{}{
					"security_score": score,
					"average_cvss":   resMap["average_cvss"],
				}
			}
		}

	case "frida":
		summary.Summary = map[string]interface{}{
			"info": "See detailed report for more info",
		}
		if resMap, ok := resultInterface.(map[string]interface{}); ok {
			// Unwrap if nested
			if inner, ok := resMap["frida"].(map[string]interface{}); ok {
				resMap = inner
			}
			summary.Summary = map[string]interface{}{
				"status":     resMap["status"],
				"logs_count": 0,
			}
			if logs, ok := resMap["logs"].([]interface{}); ok {
				summary.Summary = map[string]interface{}{
					"status":     resMap["status"],
					"logs_count": len(logs),
				}
			}
		}

	case "nmap":
		// Nmap: Open Ports, Service Names
		var openPorts []int
		var services []string
		if resMap, ok := resultInterface.(map[string]interface{}); ok {
			if hosts, ok := resMap["hosts"].([]interface{}); ok {
				for _, h := range hosts {
					if hostMap, ok := h.(map[string]interface{}); ok {
						if ports, ok := hostMap["ports"].([]interface{}); ok {
							for _, p := range ports {
								if portMap, ok := p.(map[string]interface{}); ok {
									// Extract Port ID
									if portID, ok := portMap["portid"].(json.Number); ok {
										pid, _ := portID.Int64()
										openPorts = append(openPorts, int(pid))
									} else if portID, ok := portMap["portid"].(float64); ok {
										openPorts = append(openPorts, int(portID))
									}
									// Extract Service Name
									if service, ok := portMap["service"].(map[string]interface{}); ok {
										if name, ok := service["name"].(string); ok {
											services = append(services, name)
										}
									}
								}
							}
						}
					}
				}
			}
		}
		summary.Summary = map[string]interface{}{
			"open_ports": openPorts,
			"services":   services,
			"total_open": len(openPorts),
		}

	case "owasp-zap":
		// ZAP: Alert Counts by Risk
		alertsByRisk := make(map[string]int)
		totalAlerts := 0
		if resMap, ok := resultInterface.(map[string]interface{}); ok {
			if alertsRaw, ok := resMap["alertsRaw"].(map[string]interface{}); ok {
				if alerts, ok := alertsRaw["alerts"].([]interface{}); ok {
					totalAlerts = len(alerts)
					for _, a := range alerts {
						if alertMap, ok := a.(map[string]interface{}); ok {
							if riskStr, ok := alertMap["risk"].(string); ok {
								alertsByRisk[riskStr]++
							}
						}
					}
				}
			}
		}
		summary.Summary = map[string]interface{}{
			"alerts_by_risk": alertsByRisk,
			"total_alerts":   totalAlerts,
		}

	case "openvas":
		// OpenVAS: Findings count, Severities, Max CVSS
		findingsCount := 0
		highSevCount := 0
		maxCVSS := 0.0
		var topProblems []string

		if resMap, ok := resultInterface.(map[string]interface{}); ok {
			if resultsContainer, ok := resMap["results"].(map[string]interface{}); ok {
				if findings, ok := resultsContainer["result"].([]interface{}); ok {
					findingsCount = len(findings)
					for _, finding := range findings {
						if fMap, ok := finding.(map[string]interface{}); ok {
							// Extract Severity & CVSS
							if sevStr, ok := fMap["severity"].(string); ok {
								if sevVal, err := strconv.ParseFloat(sevStr, 64); err == nil {
									if sevVal > maxCVSS {
										maxCVSS = sevVal
									}
									if sevVal >= 7.0 {
										highSevCount++
										// Add to top problems (limit to 5)
										if len(topProblems) < 5 {
											if name, ok := fMap["name"].(string); ok {
												topProblems = append(topProblems, fmt.Sprintf("%s (CVSS: %.1f)", name, sevVal))
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		summary.Summary = map[string]interface{}{
			"total_findings":      findingsCount,
			"high_critical_count": highSevCount,
			"max_cvss":            maxCVSS,
			"top_problems":        topProblems,
		}

	case "ffuf":
		// FFUF: Found URLs count & Top Matches
		foundCount := 0
		statusCodes := make(map[string]int)
		var topMatches []string

		if resMap, ok := resultInterface.(map[string]interface{}); ok {
			if results, ok := resMap["results"].([]interface{}); ok {
				foundCount = len(results)
				for _, r := range results {
					if resObj, ok := r.(map[string]interface{}); ok {
						if status, ok := resObj["status"].(float64); ok {
							statusCodes[fmt.Sprintf("%.0f", status)]++
						}
						// Collect first few URLs
						if len(topMatches) < 5 {
							if url, ok := resObj["url"].(string); ok {
								topMatches = append(topMatches, url)
							}
						}
					}
				}
			}
		}
		summary.Summary = map[string]interface{}{
			"found_urls":          foundCount,
			"status_distribution": statusCodes,
			"top_matches":         topMatches,
		}

	case "nuclei":
		// Nuclei: Findings count by severity
		count := 0
		severityMap := make(map[string]int)
		var criticalFindings []string

		parseList := func(list []interface{}) {
			count = len(list)
			for _, item := range list {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if info, ok := itemMap["info"].(map[string]interface{}); ok {
						if severity, ok := info["severity"].(string); ok {
							severityMap[severity]++
							// Collect Critical/High names
							if strings.ToLower(severity) == "critical" || strings.ToLower(severity) == "high" {
								if len(criticalFindings) < 5 {
									if name, ok := info["name"].(string); ok {
										criticalFindings = append(criticalFindings, name)
									}
								}
							}
						}
					}
				}
			}
		}

		if resList, ok := resultInterface.([]interface{}); ok {
			parseList(resList)
		} else if resMap, ok := scan.Result.(map[string]interface{}); ok {
			// sometime mapped differently
			_ = resMap
		}
		summary.Summary = map[string]interface{}{
			"findings_count":    count,
			"severity_counts":   severityMap,
			"critical_findings": criticalFindings,
		}

	default:
		// Default: pass thorough generic info or limited raw
		summary.Summary = map[string]string{"info": "See detailed report for more info"}
	}

	return summary
}

// GetBatchReportData aggregates all necessary data for the PDF report
func (s *BatchService) GetBatchReportData(
	ctx context.Context,
	batchID string,
	userID string,
) (*models.ReportData, error) {

	// 1. Fetch batch for access control
	batch, err := s.repo.FindByID(ctx, batchID)
	if err != nil {
		return nil, err
	}
	if batch == nil {
		return nil, fmt.Errorf("batch not found")
	}
	if batch.UserID != userID {
		return nil, fmt.Errorf("access denied")
	}
	// 2. Delegate to RiskService
	return s.riskService.AnalyzeBatch(batchID)
}

func guessCVSSFromSeverity(sev string) float64 {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 9.5
	case "HIGH":
		return 8.0
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 3.0
	default:
		return 0
	}
}

func defaultRecommendation(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "Apply security patch immediately and restrict exposure."
	case "MEDIUM":
		return "Review configuration and apply recommended hardening."
	case "LOW":
		return "Monitor and fix during regular maintenance."
	default:
		return ""
	}
}
func (s *BatchService) summarizeMobileScan(
	batch *models.Batch,
	tool string,
	target string,
) models.ScanResultSummary {

	summary := map[string]interface{}{
		"scan_type": "mobile",
		"status":    "done",
		"note":      "Mobile security analysis",
	}

	// ringan & aman: extract HIGH LEVEL only
	if tool == "mobsf" {
		summary["note"] = "Static mobile analysis (MobSF)"
		summary["highlights"] = map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
		}
	}

	if tool == "frida" {
		summary["note"] = "Dynamic runtime instrumentation (Frida)"
		summary["highlights"] = map[string]int{
			"hooks_detected":  0,
			"sensitive_calls": 0,
		}
	}

	return models.ScanResultSummary{
		ID:        0,
		Tool:      tool,
		Target:    target,
		CreatedAt: batch.CreatedAt,
		Summary:   summary,
	}
}
