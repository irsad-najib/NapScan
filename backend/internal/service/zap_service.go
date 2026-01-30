package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"napscan-be/internal/models"
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

// zapPollStatusWithProgress polls ZAP API and updates ScanManager progress
func (s *ZapService) zapPollStatusWithProgress(ctx context.Context, baseURL string, apiKey string, component string, scanID string, taskID string, manager *ScanManager, baseProgress int, maxProgress int) error {
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

			// Map ZAP progress (0-100) to our range (baseProgress-maxProgress)
			progress := baseProgress + (statusInt * (maxProgress - baseProgress) / 100)
			if progress > maxProgress {
				progress = maxProgress
			}
			
			manager.UpdateProgress(taskID, progress, models.StatusRunning)
			log.Printf("[ZAP_ASYNC] %s progress: %d%% (ZAP: %d%%)", component, progress, statusInt)

			if statusInt >= 100 {
				return nil
			}
		}
	}
}

// RunZapAsync is the async scan function following the contract
func RunZapAsync(ctx context.Context, taskID string, manager *ScanManager) error {
	task, err := manager.Get(taskID)
	if err != nil {
		return err
	}

	target := task.Target
	log.Printf("[ZAP_ASYNC] Starting async scan for task=%s target=%s", taskID, target)

	// Get ZAP config
	zapSvc := &ZapService{}
	baseURL := zapSvc.zapBaseURL()
	apiKey := zapSvc.zapAPIKey()

	// Initialize stealth configuration
	stealthConfig := NewStealthConfig()
	randomUA := stealthConfig.GetRandomUserAgent()
	log.Printf("[ZAP_ASYNC] Using stealth User-Agent: %s", randomUA)

	// Update to running
	manager.UpdateProgress(taskID, 0, models.StatusRunning)

	// Phase 0: Setup (avoid fuzzer detection)
	log.Printf("[ZAP_ASYNC] Configuring stealth settings")
	
	// Set randomized User-Agent
	uaQ := url.Values{}
	uaQ.Set("String", randomUA)
	if apiKey != "" {
		uaQ.Set("apikey", apiKey)
	}
	_, _ = zapSvc.zapGetJSON(ctx, baseURL, "/JSON/core/action/setOptionDefaultUserAgent/", uaQ)

	// Set request delay to avoid detection (200ms average)
	delayQ := url.Values{}
	delayQ.Set("Integer", "200") // 200ms delay between requests
	if apiKey != "" {
		delayQ.Set("apikey", apiKey)
	}
	_, _ = zapSvc.zapGetJSON(ctx, baseURL, "/JSON/ascan/action/setOptionDelayInMs/", delayQ)

	// Limit max threads to appear less aggressive
	threadsQ := url.Values{}
	threadsQ.Set("Integer", "5") // Max 5 concurrent threads
	if apiKey != "" {
		threadsQ.Set("apikey", apiKey)
	}
	_, _ = zapSvc.zapGetJSON(ctx, baseURL, "/JSON/ascan/action/setOptionThreadPerHost/", threadsQ)

	// Set realistic browser headers
	headers := stealthConfig.GetBrowserHeaders(randomUA)
	for key, value := range headers {
		if key == "User-Agent" {
			continue // Already set above
		}
		headerQ := url.Values{}
		headerQ.Set("String", key+": "+value)
		if apiKey != "" {
			headerQ.Set("apikey", apiKey)
		}
		// Add custom header via replacer (if available) or just log
		log.Printf("[ZAP_ASYNC] Setting header: %s", key)
	}

	// Phase 1: Spider scan (0-40%)
	log.Printf("[ZAP_ASYNC] Initiating spider scan")
	manager.UpdateProgress(taskID, 5, models.StatusRunning)

	// Configure replacer to ignore ffuf traffic
	log.Printf("[ZAP_ASYNC] Configuring replacer to ignore ffuf traffic")
	zapSvc.configureReplacer(ctx, baseURL, apiKey)

	spiderQ := url.Values{}
	spiderQ.Set("url", target)
	spiderQ.Set("recurse", "true")
	if apiKey != "" {
		spiderQ.Set("apikey", apiKey)
	}

	spiderRes, err := zapSvc.zapGetJSON(ctx, baseURL, "/JSON/spider/action/scan/", spiderQ)
	if err != nil {
		log.Printf("[ZAP_ASYNC] Failed to start spider: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to start spider: %w", err))
		return err
	}

	spiderID := fmt.Sprint(spiderRes["scan"])
	if spiderID == "" || spiderID == "<nil>" {
		err := fmt.Errorf("spider scan failed, no ID: %v", spiderRes)
		manager.Fail(taskID, err)
		return err
	}
	log.Printf("[ZAP_ASYNC] Spider scan started with ID=%s", spiderID)

	// Poll spider with progress (5-40%)
	if err := zapSvc.zapPollStatusWithProgress(ctx, baseURL, apiKey, "spider", spiderID, taskID, manager, 5, 40); err != nil {
		if ctx.Err() != nil {
			log.Printf("[ZAP_ASYNC] Spider scan cancelled")
			manager.UpdateProgress(taskID, 40, models.StatusStopped)
			return ctx.Err()
		}
		log.Printf("[ZAP_ASYNC] Spider scan polling failed: %v", err)
		manager.Fail(taskID, fmt.Errorf("spider scan polling failed: %w", err))
		return err
	}
	log.Printf("[ZAP_ASYNC] Spider scan completed")

	// Phase 2: Active scan (40-80%)
	log.Printf("[ZAP_ASYNC] Initiating active scan")
	manager.UpdateProgress(taskID, 45, models.StatusRunning)

	ascanQ := url.Values{}
	ascanQ.Set("url", target)
	ascanQ.Set("recurse", "true")
	if apiKey != "" {
		ascanQ.Set("apikey", apiKey)
	}

	ascanRes, err := zapSvc.zapGetJSON(ctx, baseURL, "/JSON/ascan/action/scan/", ascanQ)
	if err != nil {
		log.Printf("[ZAP_ASYNC] Failed to start active scan: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to start active scan: %w", err))
		return err
	}

	ascanID := fmt.Sprint(ascanRes["scan"])
	if ascanID == "" || ascanID == "<nil>" {
		err := fmt.Errorf("active scan failed, no ID: %v", ascanRes)
		manager.Fail(taskID, err)
		return err
	}
	log.Printf("[ZAP_ASYNC] Active scan started with ID=%s", ascanID)

	// Poll active scan with progress (45-80%)
	if err := zapSvc.zapPollStatusWithProgress(ctx, baseURL, apiKey, "ascan", ascanID, taskID, manager, 45, 80); err != nil {
		if ctx.Err() != nil {
			log.Printf("[ZAP_ASYNC] Active scan cancelled")
			manager.UpdateProgress(taskID, 80, models.StatusStopped)
			return ctx.Err()
		}
		log.Printf("[ZAP_ASYNC] Active scan polling failed: %v", err)
		manager.Fail(taskID, fmt.Errorf("active scan polling failed: %w", err))
		return err
	}
	log.Printf("[ZAP_ASYNC] Active scan completed")

	// Phase 3: Fetch alerts (80-90%)
	log.Printf("[ZAP_ASYNC] Fetching alerts")
	manager.UpdateProgress(taskID, 85, models.StatusRunning)

	alertsQ := url.Values{}
	alertsQ.Set("baseurl", target)
	alertsQ.Set("start", "0")
	alertsQ.Set("count", "9999")
	if apiKey != "" {
		alertsQ.Set("apikey", apiKey)
	}

	alertsRes, err := zapSvc.zapGetJSON(ctx, baseURL, "/JSON/core/view/alerts/", alertsQ)
	if err != nil {
		log.Printf("[ZAP_ASYNC] Failed to fetch alerts: %v", err)
		manager.Fail(taskID, fmt.Errorf("failed to fetch alerts: %w", err))
		return err
	}
	log.Printf("[ZAP_ASYNC] Alerts fetched successfully")

	// Phase 4: Prepare result (90-100%)
	manager.UpdateProgress(taskID, 90, models.StatusRunning)

	result := map[string]interface{}{
		"target":    target,
		"zapBase":   baseURL,
		"spider":    map[string]interface{}{"scanId": spiderID},
		"active":    map[string]interface{}{"scanId": ascanID},
		"alertsRaw": alertsRes,
	}

	// Complete
	manager.Complete(taskID, result)
	log.Printf("[ZAP_ASYNC] Scan completed successfully for task=%s", taskID)

	return nil
}

// Legacy ExecuteFullScan for backward compatibility
func (s *ZapService) ExecuteFullScan(ctx context.Context, target string) (map[string]interface{}, error) {
	baseURL := s.zapBaseURL()
	apiKey := s.zapAPIKey()

	log.Printf("[ZAP_SERVICE] Starting full scan on target=%s using baseURL=%s", target, baseURL)

	// 1) Spider scan
	log.Printf("[ZAP_SERVICE] Initiating spider scan")
	spiderQ := url.Values{}
	spiderQ.Set("url", target)
	spiderQ.Set("recurse", "true")
	if apiKey != "" {
		spiderQ.Set("apikey", apiKey)
	}

	spiderRes, err := s.zapGetJSON(ctx, baseURL, "/JSON/spider/action/scan/", spiderQ)
	if err != nil {
		log.Printf("[ZAP_SERVICE] Failed to start spider: %v", err)
		return nil, fmt.Errorf("failed to start spider: %w", err)
	}
	spiderID := fmt.Sprint(spiderRes["scan"])
	if spiderID == "" || spiderID == "<nil>" {
		log.Printf("[ZAP_SERVICE] Spider scan failed, no ID received")
		return nil, fmt.Errorf("spider scan failed, no ID: %v", spiderRes)
	}
	log.Printf("[ZAP_SERVICE] Spider scan started with ID=%s", spiderID)

	if err := s.zapPollStatus(ctx, baseURL, apiKey, "spider", spiderID); err != nil {
		log.Printf("[ZAP_SERVICE] Spider scan polling failed: %v", err)
		return nil, fmt.Errorf("spider scan polling failed: %w", err)
	}
	log.Printf("[ZAP_SERVICE] Spider scan completed")

	// 2) Active scan
	log.Printf("[ZAP_SERVICE] Initiating active scan")
	ascanQ := url.Values{}
	ascanQ.Set("url", target)
	ascanQ.Set("recurse", "true")
	if apiKey != "" {
		ascanQ.Set("apikey", apiKey)
	}

	ascanRes, err := s.zapGetJSON(ctx, baseURL, "/JSON/ascan/action/scan/", ascanQ)
	if err != nil {
		log.Printf("[ZAP_SERVICE] Failed to start active scan: %v", err)
		return nil, fmt.Errorf("failed to start active scan: %w", err)
	}
	ascanID := fmt.Sprint(ascanRes["scan"])
	if ascanID == "" || ascanID == "<nil>" {
		log.Printf("[ZAP_SERVICE] Active scan failed, no ID received")
		return nil, fmt.Errorf("active scan failed, no ID: %v", ascanRes)
	}
	log.Printf("[ZAP_SERVICE] Active scan started with ID=%s", ascanID)

	if err := s.zapPollStatus(ctx, baseURL, apiKey, "ascan", ascanID); err != nil {
		log.Printf("[ZAP_SERVICE] Active scan polling failed: %v", err)
		return nil, fmt.Errorf("active scan polling failed: %w", err)
	}
	log.Printf("[ZAP_SERVICE] Active scan completed")

	// 3) Fetch alerts
	log.Printf("[ZAP_SERVICE] Fetching alerts")
	alertsQ := url.Values{}
	alertsQ.Set("baseurl", target)
	alertsQ.Set("start", "0")
	alertsQ.Set("count", "9999")
	if apiKey != "" {
		alertsQ.Set("apikey", apiKey)
	}

	alertsRes, err := s.zapGetJSON(ctx, baseURL, "/JSON/core/view/alerts/", alertsQ)
	if err != nil {
		log.Printf("[ZAP_SERVICE] Failed to fetch alerts: %v", err)
		return nil, fmt.Errorf("failed to fetch alerts: %w", err)
	}
	log.Printf("[ZAP_SERVICE] Alerts fetched successfully")

	return map[string]interface{}{
		"target":    target,
		"zapBase":   baseURL,
		"spider":    map[string]interface{}{"scanId": spiderID},
		"active":    map[string]interface{}{"scanId": ascanID},
		"alertsRaw": alertsRes,
	}, nil
}

func (s *ZapService) configureReplacer(ctx context.Context, baseURL, apiKey string) {
	q := url.Values{}
	q.Set("description", "Ignore FFUF Traffic")
	q.Set("enabled", "true")
	q.Set("matchtype", "REQ_HEADER")
	q.Set("matchregex", "true")
	q.Set("matchstring", "X-Scanner-Origin: ffuf")
	q.Set("replacement", "")
	q.Set("initiators", "7") // Proxy only

	if apiKey != "" {
		q.Set("apikey", apiKey)
	}

	_, _ = s.zapGetJSON(ctx, baseURL,
		"/JSON/replacer/action/addRule/", q)
}