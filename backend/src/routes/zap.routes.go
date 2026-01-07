package routes

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

	"github.com/gin-gonic/gin"
)

type ZapRoutes struct {
	client any
}

func zapBaseURL() string {
	base := strings.TrimSpace(os.Getenv("ZAP_BASE_URL"))
	if base == "" {
		return "http://localhost:8080"
	}
	return strings.TrimRight(base, "/")
}

func zapAPIKey() string {
	// Never log this value.
	return strings.TrimSpace(os.Getenv("ZAP_API_KEY"))
}

func zapGetJSON(ctx context.Context, baseURL string, path string, query url.Values) (map[string]any, error) {
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
		// ZAP sometimes returns JSON error bodies; include body for debugging.
		return nil, fmt.Errorf("zap api request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid zap json response: %w: %s", err, strings.TrimSpace(string(body)))
	}
	return out, nil
}

func zapPollStatus(ctx context.Context, baseURL string, apiKey string, component string, scanID string) error {
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

			res, err := zapGetJSON(ctx, baseURL, "/JSON/"+component+"/view/status/", q)
			if err != nil {
				return err
			}

			rawStatus, ok := res["status"]
			if !ok {
				// Some ZAP endpoints return nested objects; fall back to scanning values.
				for _, v := range res {
					if m, ok := v.(map[string]any); ok {
						if s, ok := m["status"]; ok {
							rawStatus = s
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

func (zr *ZapRoutes) StartScan(c *gin.Context) {
	log.Println("Starting ZAP scan...")

	var zapTarget struct {
		Target string `json:"target" binding:"required"`
	}

	if err := c.ShouldBindJSON(&zapTarget); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	// Normalize target URL
	target := strings.TrimSpace(zapTarget.Target)
	if target == "" {
		c.JSON(400, gin.H{"error": "target is required"})
		return
	}
	if !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
		target = "https://" + target
	}
	if _, err := url.ParseRequestURI(target); err != nil {
		c.JSON(400, gin.H{"error": "invalid target url", "details": err.Error()})
		return
	}

	// Use timeout to prevent hanging scans
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	baseURL := zapBaseURL()
	apiKey := zapAPIKey()

	// 1) Spider scan
	spiderQ := url.Values{}
	spiderQ.Set("url", target)
	spiderQ.Set("recurse", "true")
	if apiKey != "" {
		spiderQ.Set("apikey", apiKey)
	}

	spiderRes, err := zapGetJSON(ctx, baseURL, "/JSON/spider/action/scan/", spiderQ)
	if err != nil {
		log.Printf("ZAP spider start error target=%s: %v", target, err)
		c.JSON(502, gin.H{"error": "failed to start zap spider", "details": err.Error()})
		return
	}
	spiderID := fmt.Sprint(spiderRes["scan"])
	if spiderID == "" || spiderID == "<nil>" {
		c.JSON(502, gin.H{"error": "zap spider returned no scan id", "raw": spiderRes})
		return
	}
	if err := zapPollStatus(ctx, baseURL, apiKey, "spider", spiderID); err != nil {
		log.Printf("ZAP spider status error target=%s scanId=%s: %v", target, spiderID, err)
		c.JSON(504, gin.H{"error": "zap spider timed out or failed", "details": err.Error(), "scanId": spiderID})
		return
	}

	// 2) Active scan
	ascanQ := url.Values{}
	ascanQ.Set("url", target)
	ascanQ.Set("recurse", "true")
	if apiKey != "" {
		ascanQ.Set("apikey", apiKey)
	}

	ascanRes, err := zapGetJSON(ctx, baseURL, "/JSON/ascan/action/scan/", ascanQ)
	if err != nil {
		log.Printf("ZAP ascan start error target=%s: %v", target, err)
		c.JSON(502, gin.H{"error": "failed to start zap active scan", "details": err.Error()})
		return
	}
	ascanID := fmt.Sprint(ascanRes["scan"])
	if ascanID == "" || ascanID == "<nil>" {
		c.JSON(502, gin.H{"error": "zap active scan returned no scan id", "raw": ascanRes})
		return
	}
	if err := zapPollStatus(ctx, baseURL, apiKey, "ascan", ascanID); err != nil {
		log.Printf("ZAP ascan status error target=%s scanId=%s: %v", target, ascanID, err)
		c.JSON(504, gin.H{"error": "zap active scan timed out or failed", "details": err.Error(), "scanId": ascanID})
		return
	}

	// 3) Fetch alerts
	alertsQ := url.Values{}
	alertsQ.Set("baseurl", target)
	alertsQ.Set("start", "0")
	alertsQ.Set("count", "9999")
	if apiKey != "" {
		alertsQ.Set("apikey", apiKey)
	}

	alertsRes, err := zapGetJSON(ctx, baseURL, "/JSON/core/view/alerts/", alertsQ)
	if err != nil {
		log.Printf("ZAP alerts fetch error target=%s: %v", target, err)
		c.JSON(502, gin.H{"error": "failed to fetch zap alerts", "details": err.Error()})
		return
	}

	// Respond in a stable envelope for frontend
	c.JSON(200, gin.H{
		"target":   target,
		"zapBase":  baseURL,
		"spider":   gin.H{"scanId": spiderID},
		"active":   gin.H{"scanId": ascanID},
		"alertsRaw": alertsRes,
	})
}

func (zr *ZapRoutes) SetupRoutes(rg *gin.RouterGroup) {
	zapGroup := rg.Group("/zap")
	zapGroup.POST("/scan", zr.StartScan)
}