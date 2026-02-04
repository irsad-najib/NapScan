package risk

import (
	"log"
	"math"
	"napscan-be/internal/models"
	"napscan-be/pkg/parser"
	"sort"
	"strings"
)

// Scanner weights for risk calculation
var scannerWeights = map[string]float64{
	"nuclei":    1.2,  // Template-based, high accuracy
	"openvas":   1.15, // Comprehensive CVE database
	"owasp-zap": 1.1,  // Active web scanning
	"nikto":     1.05, // Web server scanning
	"nmap":      1.0,  // Baseline network scanning
	"ffuf":      1.0,  // Directory fuzzing
	"sslyze":    1.0,  // SSL/TLS analysis
	"mobsf":     1.2,  // Static APK analysis
	"frida":     1.25, // Dynamic APK analysis
}

// GetScannerWeight returns the weight multiplier for a scanner
func GetScannerWeight(scanner string) float64 {
	if weight, ok := scannerWeights[scanner]; ok {
		return weight
	}
	return 1.0 // Default weight
}

// CalculateScannerScore calculates the risk score for a single scanner
func CalculateScannerScore(detail *models.ScannerRiskDetail) float64 {
	weight := GetScannerWeight(detail.Scanner)

	score := detail.Score

	if score == 0 {
		base := models.GetSeverityScore(detail.NormalizedSeverity)
		count := float64(len(detail.Findings))
		if count == 0 {
			count = 1
		}
		score = base*10 + count*2
	}
	score = score * weight

	return math.Round(score*100) / 100
}

// CalculateBatchRisk calculates the overall risk for a batch
func CalculateBatchRisk(batchID string, scannerDetails []models.ScannerRiskDetail) *models.BatchRiskResponse {
	if len(scannerDetails) == 0 {
		return &models.BatchRiskResponse{
			BatchID:    batchID,
			RiskScore:  0,
			RiskLevel:  models.SeverityInfo,
			RiskDetail: scannerDetails,
		}
	}
	totalScore := 0.0

	// Sort scanners alphabetically for determinism
	sort.Slice(scannerDetails, func(i, j int) bool {
		return scannerDetails[i].Scanner < scannerDetails[j].Scanner
	})

	// Calculate score for each scanner and aggregate
	for i := range scannerDetails {
		score := CalculateScannerScore(&scannerDetails[i])
		scannerDetails[i].Score = score
		totalScore += score
	}

	// Cap at 100
	maxTotal := float64(len(scannerDetails)) * 100

	if maxTotal <= 0 {
		totalScore = 0
	} else {
		totalScore = (totalScore / maxTotal) * 100
	}

	// Round to 2 decimal places
	totalScore = math.Round(totalScore*100) / 100

	// Classify risk level
	riskLevel := models.ClassifyRiskLevel(totalScore)

	log.Printf("[RISK_ENGINE] scanners=%d rawTotal=%.2f", len(scannerDetails), totalScore)
	return &models.BatchRiskResponse{
		BatchID:    batchID,
		RiskScore:  totalScore,
		RiskLevel:  riskLevel,
		RiskDetail: scannerDetails,
	}
}

// GetParser returns the appropriate parser for a scanner type
func GetParser(scannerType string) parser.ScannerParser {
	switch strings.ToLower(scannerType) {
	case "nmap":
		return parser.NewNmapParser()
	case "ffuf":
		return parser.NewFFUFParser()
	case "nuclei":
		return parser.NewNucleiParser()
	case "openvas":
		return parser.NewOpenVASParser()
	case "owasp-zap", "zap": // Handle alias
		return parser.NewZAPParser()
	case "sslyze":
		return parser.NewSSLyzeParser()
	case "mobsf":
		return parser.NewMobSFParser()
	case "frida":
		return parser.NewFridaParser()
	default:
		return nil
	}
}
