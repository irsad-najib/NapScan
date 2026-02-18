package service

import (
	"fmt"
	"math"
	"strings"
)

type CVSSService struct{}

func NewCVSSService() *CVSSService {
	return &CVSSService{}
}

// CVSSVector represents the parsed components of a CVSS v3.1 string
type CVSSVector struct {
	AV string // Attack Vector
	AC string // Attack Complexity
	PR string // Privileges Required
	UI string // User Interaction
	S  string // Scope
	C  string // Confidentiality
	I  string // Integrity
	A  string // Availability
}

// ParseVector parses a CVSS v3.1 vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
func (s *CVSSService) ParseVector(vectorStr string) (*CVSSVector, error) {
	if !strings.HasPrefix(vectorStr, "CVSS:3.1/") {
		return nil, fmt.Errorf("invalid CVSS v3.1 prefix")
	}

	parts := strings.Split(strings.TrimPrefix(vectorStr, "CVSS:3.1/"), "/")
	vector := &CVSSVector{}

	for _, part := range parts {
		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		switch key {
		case "AV":
			vector.AV = val
		case "AC":
			vector.AC = val
		case "PR":
			vector.PR = val
		case "UI":
			vector.UI = val
		case "S":
			vector.S = val
		case "C":
			vector.C = val
		case "I":
			vector.I = val
		case "A":
			vector.A = val
		}
	}

	return vector, nil
}

// CalculateScore computes the CVSS v3.1 Base Score
func (s *CVSSService) CalculateScore(vector *CVSSVector) float64 {
	// Metric Values
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[vector.AV]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[vector.AC]
	pr := 0.0
	ui := map[string]float64{"N": 0.85, "R": 0.62}[vector.UI]
	c := map[string]float64{"N": 0.00, "L": 0.22, "H": 0.56}[vector.C]
	i := map[string]float64{"N": 0.00, "L": 0.22, "H": 0.56}[vector.I]
	a := map[string]float64{"N": 0.00, "L": 0.22, "H": 0.56}[vector.A]

	// PR depends on Scope
	if vector.S == "U" {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[vector.PR]
	} else if vector.S == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}[vector.PR]
	}

	// ISS Calculation
	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

	// Impact Calculation
	impact := 0.0
	if vector.S == "U" {
		impact = 6.42 * iss
	} else if vector.S == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0.0
	}

	// Exploitability Calculation
	exploitability := 8.22 * av * ac * pr * ui

	// Base Score Calculation
	baseScore := 0.0
	if vector.S == "U" {
		baseScore = roundup(math.Min(impact+exploitability, 10))
	} else if vector.S == "C" {
		baseScore = roundup(math.Min(1.08*(impact+exploitability), 10))
	}

	return baseScore
}

// roundup rounds up to 1 decimal place
func roundup(val float64) float64 {
	intVal := int(val * 100000)
	if intVal%10000 == 0 {
		return float64(intVal/10000) / 10.0
	}
	return (math.Ceil(val * 10)) / 10.0
}

func (s *CVSSService) GetSeverity(score float64) string {
	if score == 0.0 {
		return "None"
	}
	if score >= 0.1 && score <= 3.9 {
		return "Low"
	}
	if score >= 4.0 && score <= 6.9 {
		return "Medium"
	}
	if score >= 7.0 && score <= 8.9 {
		return "High"
	}
	if score >= 9.0 && score <= 10.0 {
		return "Critical"
	}
	return "None"
}
