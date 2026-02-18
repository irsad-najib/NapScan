package handler

import (
	"context"
	"encoding/json"
	"napscan-be/pkg/logger"
	"strings"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type NucleiHandler struct {
	service      *service.NucleiService
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewNucleiHandler(s *service.NucleiService, scanRepo repository.ScanResultRepository, batchService *service.BatchService) *NucleiHandler {
	return &NucleiHandler{service: s, scanRepo: scanRepo, batchService: batchService}
}

func buildNucleiSummary(results []map[string]interface{}) map[string]interface{} {
	summary := map[string]interface{}{
		"total_findings": len(results),
		"severity_count": make(map[string]int),
		"findings":       make([]map[string]interface{}, 0),
	}

	severityCounts := make(map[string]int)
	compactFindings := make([]map[string]interface{}, 0)

	for _, result := range results {
		// Extract severity
		if info, ok := result["info"].(map[string]interface{}); ok {
			if severity, ok := info["severity"].(string); ok {
				severityCounts[severity]++
			}
		}

		// Create compact version - hanya info penting
		compact := make(map[string]interface{})
		if templateID, ok := result["template-id"].(string); ok {
			compact["template_id"] = templateID
		}
		if matched, ok := result["matched-at"].(string); ok {
			compact["matched_at"] = matched
		}
		if info, ok := result["info"].(map[string]interface{}); ok {
			compact["name"] = info["name"]
			compact["severity"] = info["severity"]
			// Limit tags to first 3 only
			if tags, ok := info["tags"].([]interface{}); ok && len(tags) > 0 {
				if len(tags) > 3 {
					compact["tags"] = tags[:3]
				} else {
					compact["tags"] = tags
				}
			}
		}
		// Hilangkan extracted-results karena bisa sangat besar
		compactFindings = append(compactFindings, compact)
	}

	summary["severity_count"] = severityCounts
	summary["findings"] = compactFindings

	return summary
}

// StartScan initiates a Nuclei scan
// @Summary Start Nuclei Scan
// @Description Run Nuclei scan on a target. Use compact=true (default) for summary, compact=false for full results (max 100)
// @Tags Nuclei
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param compact query boolean false "Return compact summary (default: true). Set to false for full results"
// @Param target body object{target=string,batch_id=string} true "Target URL or Hostname"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /nuclei/scan [post]
func (h *NucleiHandler) StartScan(c *fiber.Ctx) error {
	logger.Info("[NUCLEI] Received scan request")
	var req struct {
		Target  string `json:"target"`
		BatchID string `json:"batch_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("[NUCLEI] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		logger.Warn("[NUCLEI] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	logger.Info("[NUCLEI] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		logger.Warn("[NUCLEI] Batch ownership validation failed: %v", err)
		return err
	}

	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		logger.Warn("[NUCLEI] Missing target")
		return response.BadRequest(c, "Target is required", nil)
	}

	logger.Info("[NUCLEI] Starting scan on target=%s", req.Target)
	ctx, cancel := context.WithTimeout(c.Context(), 300*time.Second)
	defer cancel()

	results, err := h.service.ExecuteScan(ctx, req.Target)
	if err != nil {
		logger.Error("[NUCLEI] Scan execution failed: %v", err)
		return response.InternalServerError(c, "Nuclei scan failed", err)
	}
	logger.Info("[NUCLEI] Scan completed successfully with %d findings", len(results))

	// Check if compact mode is requested (default to true to avoid large responses)
	compact := c.Query("compact", "true") // Default compact=true
	isCompact := strings.ToLower(strings.TrimSpace(compact)) == "true"

	var payload fiber.Map

	if isCompact {
		logger.Info("[NUCLEI] Building compact summary")
		summary := buildNucleiSummary(results)
		payload = fiber.Map{
			"target":   req.Target,
			"summary":  summary,
			"batch_id": req.BatchID,
			"compact":  true,
		}
		// Extra check: jika compact summary masih besar, potong findings
		if findings, ok := summary["findings"].([]map[string]interface{}); ok && len(findings) > 50 {
			logger.Warn("[NUCLEI] Compact summary has %d findings, truncating to 50", len(findings))
			summary["findings"] = findings[:50]
			summary["total_findings"] = len(results)
			summary["shown_findings"] = 50
			summary["truncated"] = true
		}
	} else {
		// Limit full results to prevent too large response
		const maxFullResults = 100
		truncated := false
		displayResults := results

		if len(results) > maxFullResults {
			logger.Warn("[NUCLEI] Truncating results from %d to %d", len(results), maxFullResults)
			displayResults = results[:maxFullResults]
			truncated = true
		}

		payload = fiber.Map{
			"target":         req.Target,
			"results":        displayResults,
			"batch_id":       req.BatchID,
			"compact":        false,
			"total_count":    len(results),
			"returned_count": len(displayResults),
			"truncated":      truncated,
		}
	}

	if h.scanRepo != nil {
		dbCtx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
		defer cancel()
		_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "nuclei",
			Target:    req.Target,
			Result:    payload,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			logger.Error("[NUCLEI] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		logger.Info("[NUCLEI] Database insert success")
	}

	// Log ukuran response untuk debugging
	if jsonBytes, err := json.Marshal(payload); err == nil {
		logger.Info("[NUCLEI] Response size: %d bytes (%.2f KB)", len(jsonBytes), float64(len(jsonBytes))/1024)
		// Warning jika masih terlalu besar
		if len(jsonBytes) > 500*1024 { // 500KB
			logger.Warn("[NUCLEI] WARNING: Response size exceeds 500KB, may cause timeout")
		}
	}

	logger.Info("[NUCLEI] Request completed successfully")
	return response.Success(c, "Scan completed", payload)
}
