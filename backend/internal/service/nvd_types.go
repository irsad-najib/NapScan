package service

// NVDResponse is the standard response structure from NVD API 2.0
type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVE CVEItem `json:"cve"`
}

type CVEItem struct {
	ID               string        `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published        string        `json:"published"`
	LastModified     string        `json:"lastModified"`
	VulnStatus       string        `json:"vulnStatus"`
	Descriptions     []Description `json:"descriptions"`
	Metrics          Metrics       `json:"metrics"`
	Weaknesses       []Weakness    `json:"weaknesses"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	CvssMetricV31 []CvssMetricV31 `json:"cvssMetricV31"`
}

type CvssMetricV31 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CvssData CvssData `json:"cvssData"`
}

type CvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}
