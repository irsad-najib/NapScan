package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"napscan-be/internal/models"

	"gorm.io/gorm"
)

type CPEService struct {
	db     *gorm.DB
	apiKey string
	client *http.Client
}

func NewCPEService(db *gorm.DB) *CPEService {
	return &CPEService{
		db:     db,
		apiKey: os.Getenv("NVD_API_KEY"),
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// GenerateCPE creates a CPE 2.3 URI
func (s *CPEService) GenerateCPE(vendor, product, version string) string {
	// Simple CPE 2.3 generator
	// cpe:2.3:partition:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
	vendor = sanitizeCPEComponent(vendor)
	product = sanitizeCPEComponent(product)
	version = sanitizeCPEComponent(version)

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

func sanitizeCPEComponent(comp string) string {
	if comp == "" {
		return "*"
	}
	comp = strings.ToLower(comp)
	comp = strings.ReplaceAll(comp, " ", "_")
	comp = strings.ReplaceAll(comp, ":", "\\:") // Escape colons
	return comp
}

// ResolveCVEs queries NVD for CVEs associated with a CPE
func (s *CPEService) ResolveCVEs(ctx context.Context, cpeURI string) ([]models.CVECache, error) {
	// Note: NVD API rate limits apply.

	url := fmt.Sprintf("%s?cpeName=%s", nvdAPIURL, cpeURI) // Assuming nvdAPIURL is exported or available (it is const in cve_service, need to make sure traverse package or just redefine constant)
	// Actually nvdAPIURL is in cve_service.go package service, so it is shared in package scope.

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []models.CVECache{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}

	var data NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var foundCVEs []models.CVECache

	for _, v := range data.Vulnerabilities {
		metrics := v.CVE.Metrics.CvssMetricV31
		var score float64
		var vector, severity string
		if len(metrics) > 0 {
			score = metrics[0].CvssData.BaseScore
			vector = metrics[0].CvssData.VectorString
			severity = metrics[0].CvssData.BaseSeverity
		}

		desc := ""
		if len(v.CVE.Descriptions) > 0 {
			desc = v.CVE.Descriptions[0].Value
		}

		cve := models.CVECache{
			CVEID:       v.CVE.ID,
			CVSSScore:   score,
			CVSSVector:  vector,
			Severity:    severity,
			Description: desc,
			LastSynced:  time.Now(),
		}

		// Cache it
		if err := s.db.Save(&cve).Error; err != nil {
			log.Printf("[CPEService] Failed to cache CVE %s: %v", cve.CVEID, err)
		}

		foundCVEs = append(foundCVEs, cve)
	}

	// Sort by score descending
	sort.Slice(foundCVEs, func(i, j int) bool {
		return foundCVEs[i].CVSSScore > foundCVEs[j].CVSSScore
	})

	return foundCVEs, nil
}
