package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type ZapService struct{}

func NewZapService() *ZapService {
	return &ZapService{}
}

func (s *ZapService) zapBaseURL() string {
	base := strings.TrimSpace(os.Getenv("ZAP_BASE_URL"))
	if base == "" {
		return "http://localhost:8080"
	}
	return strings.TrimRight(base, "/")
}

func (s *ZapService) zapAPIKey() string {
	return strings.TrimSpace(os.Getenv("ZAP_API_KEY"))
}

func (s *ZapService) zapGetJSON(ctx context.Context, baseURL string, path string, query url.Values) (map[string]interface{}, error) {
	fullURL := baseURL + path
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("zap api request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid zap json response: %w: %s", err, strings.TrimSpace(string(body)))
	}
	return out, nil
}

func (s *ZapService) zapPollStatus(ctx context.Context, baseURL string, apiKey string, component string, scanID string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			q := url.Values{}
			q.Set("scanId", scanID)
			if apiKey != "" {
				q.Set("apikey", apiKey)
			}

			res, err := s.zapGetJSON(ctx, baseURL, "/JSON/"+component+"/view/status/", q)
			if err != nil {
				return err
			}

			rawStatus, ok := res["status"]
			if !ok {
				for _, v := range res {
					if m, ok := v.(map[string]interface{}); ok {
						if stat, ok := m["status"]; ok {
							rawStatus = stat
							break
						}
					}
				}
			}

			statusStr := fmt.Sprint(rawStatus)
			statusInt, err := strconv.Atoi(statusStr)
			if err != nil {
				return fmt.Errorf("unexpected zap status value: %v", rawStatus)
			}
			if statusInt >= 100 {
				return nil
			}
		}
	}
}

func (s *ZapService) ExecuteFullScan(ctx context.Context, target string) (map[string]interface{}, error) {
	baseURL := s.zapBaseURL()
	apiKey := s.zapAPIKey()

	// 1) Spider scan
	spiderQ := url.Values{}
	spiderQ.Set("url", target)
	spiderQ.Set("recurse", "true")
	if apiKey != "" {
		spiderQ.Set("apikey", apiKey)
	}

	spiderRes, err := s.zapGetJSON(ctx, baseURL, "/JSON/spider/action/scan/", spiderQ)
	if err != nil {
		return nil, fmt.Errorf("failed to start spider: %w", err)
	}
	spiderID := fmt.Sprint(spiderRes["scan"])
	if spiderID == "" || spiderID == "<nil>" {
		return nil, fmt.Errorf("spider scan failed, no ID: %v", spiderRes)
	}

	if err := s.zapPollStatus(ctx, baseURL, apiKey, "spider", spiderID); err != nil {
		return nil, fmt.Errorf("spider scan polling failed: %w", err)
	}

	// 2) Active scan
	ascanQ := url.Values{}
	ascanQ.Set("url", target)
	ascanQ.Set("recurse", "true")
	if apiKey != "" {
		ascanQ.Set("apikey", apiKey)
	}

	ascanRes, err := s.zapGetJSON(ctx, baseURL, "/JSON/ascan/action/scan/", ascanQ)
	if err != nil {
		return nil, fmt.Errorf("failed to start active scan: %w", err)
	}
	ascanID := fmt.Sprint(ascanRes["scan"])
	if ascanID == "" || ascanID == "<nil>" {
		return nil, fmt.Errorf("active scan failed, no ID: %v", ascanRes)
	}

	if err := s.zapPollStatus(ctx, baseURL, apiKey, "ascan", ascanID); err != nil {
		return nil, fmt.Errorf("active scan polling failed: %w", err)
	}

	// 3) Fetch alerts
	alertsQ := url.Values{}
	alertsQ.Set("baseurl", target)
	alertsQ.Set("start", "0")
	alertsQ.Set("count", "9999")
	if apiKey != "" {
		alertsQ.Set("apikey", apiKey)
	}

	alertsRes, err := s.zapGetJSON(ctx, baseURL, "/JSON/core/view/alerts/", alertsQ)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch alerts: %w", err)
	}

	return map[string]interface{}{
		"target":   target,
		"zapBase":  baseURL,
		"spider":   map[string]interface{}{"scanId": spiderID},
		"active":   map[string]interface{}{"scanId": ascanID},
		"alertsRaw": alertsRes,
	}, nil
}
