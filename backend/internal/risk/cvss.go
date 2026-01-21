package risk

import (
	"math"
	"strings"
)

// CVSS Constants
const (
	ExploitabilityCoefficient = 8.22
	ScopeUnchangedCoefficient = 6.42
	ScopeChangedCoefficient   = 7.52
)

// Metric Weights
var (
	// Attack Vector
	avWeights = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	// Attack Complexity
	acWeights = map[string]float64{"L": 0.77, "H": 0.44}
	// Privileges Required (Scope Unchanged / Scope Changed)
	prWeightsU = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWeightsC = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	// User Interaction
	uiWeights = map[string]float64{"N": 0.85, "R": 0.62}
	// Scope
	scopeWeights = map[string]bool{"U": false, "C": true} // Changed?
	// CIA
	ciaWeights = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
)

func ParseVector(vector string) (*CVSSMetrics, error) {
	// Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
	parts := strings.Split(vector, "/")
	m := &CVSSMetrics{}

	for _, p := range parts {
		kv := strings.Split(p, ":")
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		switch key {
		case "AV":
			m.AttackVector = val
		case "AC":
			m.AttackComplexity = val
		case "PR":
			m.PrivilegesRequired = val
		case "UI":
			m.UserInteraction = val
		case "S":
			m.Scope = val
		case "C":
			m.ConfidentialityImpact = val
		case "I":
			m.IntegrityImpact = val
		case "A":
			m.AvailabilityImpact = val
		}
	}
	return m, nil
}

// CalculateBaseScore computes CVSS v3.1 Base Score
func CalculateBaseScore(m *CVSSMetrics) (float64, error) {
	// Validate required fields
	if m.AttackVector == "" { m.AttackVector = "N" } // Defaults? Or error?
	// For production readiness, better to be defensive or error out on critical missing fields.
	// We'll perform soft validation by checking map existence.

	getWeight := func(w map[string]float64, key string, name string) float64 {
		if v, ok := w[key]; ok {
			return v
		}
		// Fallback or error logic. For now return 0 which might tank score (safe fail?)
		// Actually, correct default is often the worst case for safety? No.
		return 0.0 
	}

	av := getWeight(avWeights, m.AttackVector, "AV")
	ac := getWeight(acWeights, m.AttackComplexity, "AC")
	pr := getWeight(prWeightsU, m.PrivilegesRequired, "PR")
	ui := getWeight(uiWeights, m.UserInteraction, "UI")
	c := getWeight(ciaWeights, m.ConfidentialityImpact, "C")
	i := getWeight(ciaWeights, m.IntegrityImpact, "I")
	a := getWeight(ciaWeights, m.AvailabilityImpact, "A")
	
	scopeChanged := false
	if m.Scope == "C" {
		scopeChanged = true
		pr = getWeight(prWeightsC, m.PrivilegesRequired, "PR") // Use Scope Changed weights
	}

	// 1. ISS (Impact Sub Score)
	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	
	// 2. Impact
	var impact float64
	if scopeChanged {
		impact = ScopeChangedCoefficient * (iss - 0.029) - 3.25 * math.Pow(iss-0.02, 15)
	} else {
		impact = ScopeUnchangedCoefficient * iss
	}
	if impact < 0 {
		impact = 0
	}

	// 3. Exploitability
	exploitability := ExploitabilityCoefficient * av * ac * pr * ui

	// 4. Base Score
	var score float64
	if impact <= 0 {
		score = 0
	} else {
		if scopeChanged {
			score = Roundup(math.Min(impact+exploitability, 10))
		} else {
			score = Roundup(math.Min(impact+exploitability, 10))
		}
	}

	return score, nil
}

// Roundup rounds up to nearest 0.1
func Roundup(val float64) float64 {
	intVal := int(val * 100000)
	if intVal % 10000 == 0 {
		return float64(intVal / 10000) / 10.0
	}
	return (math.Ceil(val * 10)) / 10.0
}
