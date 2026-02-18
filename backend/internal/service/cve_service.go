package service

import (
	"context"
	"encoding/json"
	"fmt"
	"napscan-be/pkg/logger"
	"net/http"
	"os"
	"sync"
	"time"

	"napscan-be/internal/models"

	"gorm.io/gorm"
)

const nvdAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type CVEService struct {
	db        *gorm.DB
	apiKey    string
	client    *http.Client
	mu        sync.Mutex
	inflight  map[string]chan struct{}
	rateLimit <-chan time.Time
}

func NewCVEService(db *gorm.DB) *CVEService {
	apiKey := os.Getenv("NVD_API_KEY")
	rate := 6 * time.Second // Default without API key (approx 5 requests per 30s)
	if apiKey != "" {
		rate = 600 * time.Millisecond // With API key (approx 50 requests per 30s)
	}

	return &CVEService{
		db:        db,
		apiKey:    apiKey,
		client:    &http.Client{Timeout: 30 * time.Second},
		inflight:  make(map[string]chan struct{}),
		rateLimit: time.Tick(rate),
	}
}

// GetCVE returns CVE details, fetching from NVD if not cached
func (s *CVEService) GetCVE(ctx context.Context, cveID string) (*models.CVECache, error) {
	// 1. Check local cache
	var cached models.CVECache
	if err := s.db.Where("cve_id = ?", cveID).First(&cached).Error; err == nil {
		// valid cache found
		return &cached, nil
	} else if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	// 2. Fetch from NVD with single-flight protection
	s.mu.Lock()
	if ch, ok := s.inflight[cveID]; ok {
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Retry cache check after wait
		return s.GetCVE(ctx, cveID)
	}
	ch := make(chan struct{})
	s.inflight[cveID] = ch
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.inflight, cveID)
		close(ch)
		s.mu.Unlock()
	}()

	// 3. fetch from API
	<-s.rateLimit // Respect rate limit

	<-s.rateLimit // Respect rate limit

	logger.Info("[CVEService] Fetching %s from NVD", cveID)
	cveData, err := s.fetchFromNVD(ctx, cveID)
	if err != nil {
		return nil, err
	}

	// 4. Save to cache
	if err := s.db.Create(cveData).Error; err != nil {
		logger.Warn("[CVEService] Failed to cache %s: %v", cveID, err)
	}

	return cveData, nil
}

func (s *CVEService) fetchFromNVD(ctx context.Context, cveID string) (*models.CVECache, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", nvdAPIURL+"?cveId="+cveID, nil)
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}

	var data NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode NVD response: %w", err)
	}

	if len(data.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found in NVD", cveID)
	}

	v := data.Vulnerabilities[0].CVE

	cve := &models.CVECache{
		CVEID:      v.ID,
		LastSynced: time.Now(),
		UpdatedAt:  time.Now(),
		CreatedAt:  time.Now(),
	}

	// Description
	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			cve.Description = d.Value
			break
		}
	}

	// Metrics (CVSS v3.1)
	if len(v.Metrics.CvssMetricV31) > 0 {
		m := v.Metrics.CvssMetricV31[0].CvssData
		cve.CVSSScore = m.BaseScore
		cve.CVSSVector = m.VectorString
		cve.Severity = m.BaseSeverity
	}

	// Weaknesses (CWE)
	if len(v.Weaknesses) > 0 {
		for _, w := range v.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" {
					cweID := d.Value
					cve.CWEID = &cweID
					break
				}
			}
			if cve.CWEID != nil {
				break
			}
		}
	}

	return cve, nil
}
