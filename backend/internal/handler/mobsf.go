package handler

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type MobSFHandler struct {
	scanRepo     repository.ScanResultRepository
	batchService *service.BatchService
}

func NewMobSFHandler(scanRepo repository.ScanResultRepository, batchService *service.BatchService) *MobSFHandler {
	return &MobSFHandler{scanRepo: scanRepo, batchService: batchService}
}

// UploadMobSFFile uploads a file for MobSF analysis
// @Summary Upload file for MobSF
// @Description Upload APK/IPA/ZIP file for analysis
// @Tags MobSF
// @Accept multipart/form-data
// @Security BearerAuth
// @Produce json
// @Param batch_id formData string true "Batch ID"
// @Param file formData file true "File to upload"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /mobsf/upload [post]
func (h *MobSFHandler) UploadMobSFFile(c *fiber.Ctx) error {
	// Get the file from the request
	fileHeader, err := c.FormFile("file")
	if err != nil {
		return response.BadRequest(c, "Failed to get file from request", err)
	}

	// Get batch_id from form data
	batchID := c.FormValue("batch_id")
	if batchID == "" {
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	if err := h.batchService.ValidateBatchOwnership(c, batchID); err != nil {
		return err
	}

	// Open the uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		return response.InternalServerError(c, "Failed to open uploaded file", err)
	}
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	mobsf := service.NewMobSFService()

	info, uploadRaw, err := mobsf.Upload(ctx, fileHeader.Filename, file)
	if err != nil {
		if isMobSFDebug() {
			log.Printf("[mobsf] upload error: %v", err)
		}
		return response.Error(c, fiber.StatusBadGateway, "MobSF upload failed", err.Error())
	}

	payload := fiber.Map{
		"hash":      info.Hash,
		"scan_type": info.ScanType,
		"file_name": info.FileName,
		"upload":    uploadRaw,
		"batch_id":  batchID,
	}

	return response.Success(c, "MobSF upload completed", payload)
}

// StartMobSFScan starts a scan in MobSF for the uploaded file
// @Summary Start MobSF Scan
// @Description Initiates a scan in MobSF for the uploaded file
// @Tags MobSF
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param compact query boolean false "Return a small summary instead of full scan+report JSON"
// @Param request body models.MobSFScanRequest true "Scan request"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /mobsf/scan [post]
func (h *MobSFHandler) StartMobSFScan(c *fiber.Ctx) error {
	var req models.MobSFScanRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		return err
	}

	hash := strings.TrimSpace(req.Hash)
	if hash == "" {
		return response.BadRequest(c, "hash is required", nil)
	}
	if err := validateMobSFHash(hash); err != nil {
		return response.BadRequest(c, "invalid hash", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()

	mobsf := service.NewMobSFService()

	info := service.MobSFFileInfo{
		Hash:     hash,
		ScanType: strings.TrimSpace(req.ScanType),
		FileName: strings.TrimSpace(req.FileName),
	}

	if isMobSFDebug() {
		log.Printf("[mobsf] scan start hash=%s scan_type=%s file_name=%s", info.Hash, info.ScanType, info.FileName)
	}

	scanRaw, err := mobsf.Scan(ctx, info)
	if err != nil {
		if isMobSFDebug() {
			log.Printf("[mobsf] scan error: %v", err)
		}
		return response.Error(c, fiber.StatusBadGateway, "MobSF scan failed", err.Error())
	}

	// Some MobSF setups might need a brief moment to build report.
	var reportRaw map[string]interface{}
	var lastErr error
	for i := 0; i < 5; i++ {
		if err := ctx.Err(); err != nil {
			return response.Error(c, fiber.StatusBadGateway, "MobSF report_json failed", err.Error())
		}
		reportRaw, lastErr = mobsf.ReportJSON(ctx, info)
		if lastErr == nil {
			break
		}
		t := time.Duration(i+1) * 500 * time.Millisecond
		select {
		case <-ctx.Done():
			return response.Error(c, fiber.StatusBadGateway, "MobSF report_json failed", ctx.Err().Error())
		case <-time.After(t):
		}
	}
	if lastErr != nil {
		return response.Error(c, fiber.StatusBadGateway, "MobSF report_json failed", lastErr.Error())
	}

	compact := isTruthy(c.Query("compact"))
	if compact {
		summary := buildMobSFSummary(info, scanRaw, reportRaw)
		payload := fiber.Map{
			"hash":      info.Hash,
			"scan_type": info.ScanType,
			"file_name": info.FileName,
			"summary":   summary,
			"batch_id":  req.BatchID,
		}

		if h.scanRepo != nil {
			dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
				BatchID:   req.BatchID,
				Tool:      "mobsf",
				Target:    info.Hash,
				Result:    payload,
				CreatedAt: time.Now().UTC(),
			})
			if dbErr != nil {
				return response.InternalServerError(c, "Failed to save scan result", dbErr)
			}
		}

		return response.Success(c, "MobSF scan completed", payload)
	}

	payload := fiber.Map{
		"hash":      info.Hash,
		"scan_type": info.ScanType,
		"file_name": info.FileName,
		"scan":      scanRaw,
		"report":    reportRaw,
		"batch_id":  req.BatchID,
	}

	if h.scanRepo != nil {
		dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, dbErr := h.scanRepo.Insert(dbCtx, &models.ScanResult{
			BatchID:   req.BatchID,
			Tool:      "mobsf",
			Target:    info.Hash,
			Result:    payload,
			CreatedAt: time.Now().UTC(),
		})
		if dbErr != nil {
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
	}

	return response.Success(c, "MobSF scan completed", payload)
}	

func isMobSFDebug() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("MOBSF_DEBUG")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func validateMobSFHash(hash string) error {
	if len(hash) != 32 {
		return fiber.NewError(fiber.StatusBadRequest, "hash must be 32 hex chars")
	}
	// MobSF commonly uses MD5 hashes (32 hex). We only validate shape here.
	for _, r := range hash {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return fiber.NewError(fiber.StatusBadRequest, "hash must be hex")
	}
	return nil
}

func isTruthy(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}

func buildMobSFSummary(info service.MobSFFileInfo, scanRaw, reportRaw map[string]interface{}) fiber.Map {
	asString := func(v interface{}) string {
		if v == nil {
			return ""
		}
		switch t := v.(type) {
		case string:
			return strings.TrimSpace(t)
		case float64:
			// JSON numbers decode as float64. Render without trailing .0 when possible.
			if t == float64(int64(t)) {
				return fmt.Sprintf("%d", int64(t))
			}
			return fmt.Sprintf("%v", t)
		case bool:
			if t {
				return "true"
			}
			return "false"
		default:
			return strings.TrimSpace(fmt.Sprint(v))
		}
	}
	getStr := func(m map[string]interface{}, key string) string {
		if m == nil {
			return ""
		}
		v, ok := m[key]
		if !ok {
			return ""
		}
		return asString(v)
	}
	asMap := func(v interface{}) map[string]interface{} {
		if v == nil {
			return nil
		}
		m, _ := v.(map[string]interface{})
		return m
	}
	asSlice := func(v interface{}) []interface{} {
		if v == nil {
			return nil
		}
		s, _ := v.([]interface{})
		return s
	}
	truncate := func(s string, max int) string {
		s = strings.TrimSpace(s)
		if max <= 0 {
			return ""
		}
		if len(s) <= max {
			return s
		}
		// keep a tiny suffix room for ellipsis
		if max <= 3 {
			return s[:max]
		}
		return s[:max-3] + "..."
	}
	uniqueStrings := func(in []string) []string {
		seen := make(map[string]struct{}, len(in))
		out := make([]string, 0, len(in))
		for _, s := range in {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
		sort.Strings(out)
		return out
	}

	// Prefer report_json fields as they tend to be richer.
	md5 := getStr(reportRaw, "md5")
	sha1 := getStr(reportRaw, "sha1")
	sha256 := getStr(reportRaw, "sha256")
	if md5 == "" {
		md5 = getStr(scanRaw, "md5")
	}
	if sha1 == "" {
		sha1 = getStr(scanRaw, "sha1")
	}
	if sha256 == "" {
		sha256 = getStr(scanRaw, "sha256")
	}

	// --- Permissions ---
	permStatusCounts := fiber.Map{}
	dangerousPerms := make([]fiber.Map, 0)
	permissions := asMap(reportRaw["permissions"])
	if permissions != nil {
		for permName, raw := range permissions {
			p := asMap(raw)
			status := strings.ToLower(getStr(p, "status"))
			if status == "" {
				status = "unknown"
			}
			prev, ok := permStatusCounts[status]
			if !ok {
				permStatusCounts[status] = 1
			} else {
				// counts are integers; keep as int for JSON encoder.
				permStatusCounts[status] = prev.(int) + 1
			}
			if status == "dangerous" {
				dangerousPerms = append(dangerousPerms, fiber.Map{
					"permission":   permName,
					"info":         truncate(getStr(p, "info"), 200),
					"description":  truncate(getStr(p, "description"), 300),
					"protection":   status,
				})
			}
		}
		sort.Slice(dangerousPerms, func(i, j int) bool {
			return asString(dangerousPerms[i]["permission"]) < asString(dangerousPerms[j]["permission"])
		})
		if len(dangerousPerms) > 25 {
			dangerousPerms = dangerousPerms[:25]
		}
	}

	// --- AppSec (findings by severity) ---
	appsec := asMap(reportRaw["appsec"])
	getFindingList := func(section string, maxItems int) ([]fiber.Map, int) {
		items := make([]fiber.Map, 0)
		s := asSlice(appsec[section])
		for _, raw := range s {
			m := asMap(raw)
			if m == nil {
				continue
			}
			items = append(items, fiber.Map{
				"title":       truncate(getStr(m, "title"), 180),
				"section":     truncate(getStr(m, "section"), 60),
				"description": truncate(getStr(m, "description"), 400),
			})
			if maxItems > 0 && len(items) >= maxItems {
				break
			}
		}
		return items, len(s)
	}
	highItems, highTotal := getFindingList("high", 10)
	warningItems, warningTotal := getFindingList("warning", 10)
	hotspotItems, hotspotTotal := getFindingList("hotspot", 10)
	infoItems, infoTotal := getFindingList("info", 10)
	secureItems, secureTotal := getFindingList("secure", 10)

	// --- Manifest findings ---
	manifest := asMap(reportRaw["manifest_analysis"])
	manifestSummary := asMap(manifest["manifest_summary"])
	manifestFindingsOut := make([]fiber.Map, 0)
	manifestFindings := asSlice(manifest["manifest_findings"])
	for _, raw := range manifestFindings {
		m := asMap(raw)
		if m == nil {
			continue
		}
		manifestFindingsOut = append(manifestFindingsOut, fiber.Map{
			"severity":    strings.ToLower(getStr(m, "severity")),
			"rule":        truncate(getStr(m, "rule"), 80),
			"title":       truncate(getStr(m, "title"), 180),
			"description": truncate(getStr(m, "description"), 400),
		})
		if len(manifestFindingsOut) >= 10 {
			break
		}
	}

	// --- Certificate findings ---
	cert := asMap(reportRaw["certificate_analysis"])
	certSummary := asMap(cert["certificate_summary"])
	certFindings := asSlice(cert["certificate_findings"])
	certFindingsOut := make([]fiber.Map, 0)
	for _, raw := range certFindings {
		row := asSlice(raw)
		if len(row) < 3 {
			continue
		}
		certFindingsOut = append(certFindingsOut, fiber.Map{
			"severity":     strings.ToLower(asString(row[0])),
			"title":        truncate(asString(row[1]), 180),
			"description":  truncate(asString(row[2]), 400),
		})
		if len(certFindingsOut) >= 10 {
			break
		}
	}

	// --- Trackers ---
	trackers := asMap(reportRaw["trackers"])
	trackerNames := make([]string, 0)
	trackerList := asSlice(trackers["trackers"])
	for _, raw := range trackerList {
		m := asMap(raw)
		if m != nil {
			name := getStr(m, "name")
			if name != "" {
				trackerNames = append(trackerNames, name)
				continue
			}
		}
		if s, ok := raw.(string); ok {
			trackerNames = append(trackerNames, s)
		}
	}
	trackerNames = uniqueStrings(trackerNames)
	if len(trackerNames) > 30 {
		trackerNames = trackerNames[:30]
	}

	// --- URLs & Domains ---
	urlEntries := asSlice(reportRaw["urls"])
	flatURLs := make([]string, 0)
	for _, raw := range urlEntries {
		m := asMap(raw)
		if m == nil {
			continue
		}
		urls := asSlice(m["urls"])
		for _, u := range urls {
			flatURLs = append(flatURLs, asString(u))
		}
	}
	flatURLs = uniqueStrings(flatURLs)
	urlSample := flatURLs
	if len(urlSample) > 30 {
		urlSample = urlSample[:30]
	}

	domains := asMap(reportRaw["domains"])
	domainNames := make([]string, 0, len(domains))
	suspiciousDomains := make([]fiber.Map, 0)
	for domain, raw := range domains {
		domainNames = append(domainNames, domain)
		m := asMap(raw)
		if m == nil {
			continue
		}
		bad := strings.ToLower(getStr(m, "bad"))
		of := m["ofac"]
		ofStr := strings.ToLower(asString(of))
		if bad == "yes" || ofStr == "true" {
			suspiciousDomains = append(suspiciousDomains, fiber.Map{
				"domain": domain,
				"bad":    bad,
				"ofac":   ofStr == "true",
			})
		}
	}
	sort.Strings(domainNames)
	if len(domainNames) > 50 {
		domainNames = domainNames[:50]
	}
	if len(suspiciousDomains) > 30 {
		suspiciousDomains = suspiciousDomains[:30]
	}

	// --- Secrets ---
	secretsRaw := asSlice(reportRaw["secrets"])
	secrets := make([]string, 0)
	for _, s := range secretsRaw {
		secrets = append(secrets, truncate(asString(s), 120))
	}
	secrets = uniqueStrings(secrets)
	secretSample := secrets
	if len(secretSample) > 30 {
		secretSample = secretSample[:30]
	}

	// --- Small metadata ---
	exportedCount := asMap(reportRaw["exported_count"])
	activities := asSlice(reportRaw["activities"])
	services := asSlice(reportRaw["services"])
	receivers := asSlice(reportRaw["receivers"])
	providers := asSlice(reportRaw["providers"])

	return fiber.Map{
		"hash": info.Hash,
		"identity": fiber.Map{
			"app_name":      getStr(reportRaw, "app_name"),
			"package_name":  getStr(reportRaw, "package_name"),
			"file_name":     getStr(reportRaw, "file_name"),
			"version_name":  getStr(reportRaw, "version_name"),
			"main_activity": getStr(reportRaw, "main_activity"),
			"icon_path":     getStr(reportRaw, "icon_path"),
			"timestamp":     getStr(reportRaw, "timestamp"),
		},
		"hashes": fiber.Map{
			"md5":    md5,
			"sha1":   sha1,
			"sha256": sha256,
		},
		"sdk": fiber.Map{
			"min_sdk":    getStr(reportRaw, "min_sdk"),
			"target_sdk": getStr(reportRaw, "target_sdk"),
			"max_sdk":    getStr(reportRaw, "max_sdk"),
		},
		"components": fiber.Map{
			"activities":      len(activities),
			"services":        len(services),
			"receivers":       len(receivers),
			"providers":       len(providers),
			"exported_count":  exportedCount,
		},
		"permissions": fiber.Map{
			"status_counts":   permStatusCounts,
			"dangerous_sample": dangerousPerms,
		},
		"findings": fiber.Map{
			"security_score": getStr(appsec, "security_score"),
			"totals": fiber.Map{
				"high":    highTotal,
				"warning": warningTotal,
				"hotspot": hotspotTotal,
				"info":    infoTotal,
				"secure":  secureTotal,
			},
			"high":    highItems,
			"warning": warningItems,
			"hotspot": hotspotItems,
			"info":    infoItems,
			"secure":  secureItems,
		},
		"manifest": fiber.Map{
			"summary":  manifestSummary,
			"findings": manifestFindingsOut,
		},
		"certificate": fiber.Map{
			"summary":  certSummary,
			"findings": certFindingsOut,
		},
		"network": fiber.Map{
			"urls_total":   len(flatURLs),
			"urls_sample":  urlSample,
			"domains_total": len(domains),
			"domains_sample": domainNames,
			"suspicious_domains": suspiciousDomains,
		},
		"trackers": fiber.Map{
			"detected_trackers": trackers["detected_trackers"],
			"total_trackers":    trackers["total_trackers"],
			"trackers_sample":   trackerNames,
		},
		"secrets": fiber.Map{
			"total":  len(secrets),
			"sample": secretSample,
		},
		"meta": fiber.Map{
			"mobsf_version": getStr(reportRaw, "version"),
			"has_scan":      scanRaw != nil,
			"has_report":    reportRaw != nil,
		},
	}
}