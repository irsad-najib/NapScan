package risk

// RiskLevel represents the severity classification
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// ContextFactors defines the environmental context for risk calculation
type ContextFactors struct {
	AssetCriticality string // "low", "medium", "high"
	Exposure         string // "internal", "partner", "public"
	Environment      string // "dev", "staging", "prod"
}

// CVSSMetrics represents the broken down CVSS v3.1 vector
type CVSSMetrics struct {
	AttackVector          string // AV
	AttackComplexity      string // AC
	PrivilegesRequired    string // PR
	UserInteraction       string // UI
	Scope                 string // S
	ConfidentialityImpact string // C
	IntegrityImpact       string // I
	AvailabilityImpact    string // A
}

// RiskInput represents the input payload for calculation
type RiskInput struct {
	VectorString string       `json:"vector_string,omitempty"` // e.g. "CVSS:3.1/AV:N/AC:L..."
	Metrics      *CVSSMetrics `json:"metrics,omitempty"`       // Optional structured input
}

// RiskResult represents the final calculated output
type RiskResult struct {
	BaseScore      float64   `json:"base_score"`
	FinalScore     float64   `json:"final_score"`
	RiskLevel      RiskLevel `json:"risk_level"`
	Vector         string    `json:"vector"`
	Explanation    []string  `json:"explanation"`
	ContextFactors map[string]float64 `json:"context_factors"`
}
