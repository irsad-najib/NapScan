package risk

import (
	"fmt"
	"math"
)

// CalculateRisk performs the full risk assessment
func CalculateRisk(input RiskInput, ctx ContextFactors) (RiskResult, error) {
	var metrics *CVSSMetrics
	var err error
	var vector string

	// 1. Determine Metrics from Input
	if input.VectorString != "" {
		metrics, err = ParseVector(input.VectorString)
		if err != nil {
			return RiskResult{}, fmt.Errorf("invalid vector: %w", err)
		}
		vector = input.VectorString
	} else if input.Metrics != nil {
		metrics = input.Metrics
		// Reconstruct vector string (simplified)
		vector = fmt.Sprintf("AV:%s/AC:%s/...", metrics.AttackVector, metrics.AttackComplexity)
	} else {
		return RiskResult{}, fmt.Errorf("no input provided")
	}

	// 2. Calculate Base Score
	baseScore, err := CalculateBaseScore(metrics)
	if err != nil {
		return RiskResult{}, err
	}

	// 3. Apply Context Modifiers
	assetMod := getContextWeight(ctx.AssetCriticality, map[string]float64{"low": 1.0, "medium": 1.2, "high": 1.5}, 1.0)
	exposureMod := getContextWeight(ctx.Exposure, map[string]float64{"internal": 1.0, "partner": 1.2, "public": 1.4}, 1.0)
	envMod := getContextWeight(ctx.Environment, map[string]float64{"dev": 0.8, "staging": 1.0, "prod": 1.2}, 1.2)

	rawFinal := baseScore * assetMod * exposureMod * envMod
	finalScore := math.Min(rawFinal, 10.0)
	finalScore = math.Round(finalScore*10) / 10 // Round to 1 decimal

	// 4. Determine Risk Level
	var level RiskLevel
	switch {
	case finalScore == 0:
		level = "NONE"
	case finalScore < 4.0:
		level = RiskLow
	case finalScore < 7.0:
		level = RiskMedium
	case finalScore < 9.0:
		level = RiskHigh
	default:
		level = RiskCritical
	}

	// 5. Generate Explanation
	explanation := []string{
		fmt.Sprintf("Base CVSS Score: %.1f", baseScore),
		fmt.Sprintf("Asset Criticality (%s): x%.1f", ctx.AssetCriticality, assetMod),
		fmt.Sprintf("Exposure (%s): x%.1f", ctx.Exposure, exposureMod),
		fmt.Sprintf("Environment (%s): x%.1f", ctx.Environment, envMod),
	}

	return RiskResult{
		BaseScore:   baseScore,
		FinalScore:  finalScore,
		RiskLevel:   level,
		Vector:      vector,
		Explanation: explanation,
		ContextFactors: map[string]float64{
			"asset_criticality": assetMod,
			"exposure":          exposureMod,
			"environment":       envMod,
		},
	}, nil
}

func getContextWeight(val string, weights map[string]float64, def float64) float64 {
	if v, ok := weights[val]; ok {
		return v
	}
	return def
}
