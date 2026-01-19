package handler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
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
	lifecycle    *service.LifecycleService
}

func NewMobSFHandler(scanRepo repository.ScanResultRepository, batchService *service.BatchService, lifecycle *service.LifecycleService) *MobSFHandler {
	return &MobSFHandler{scanRepo: scanRepo, batchService: batchService, lifecycle: lifecycle}
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
	log.Printf("[MOBSF] Received upload request")
	// Get the file from the request
	fileHeader, err := c.FormFile("file")
	if err != nil {
		log.Printf("[MOBSF] Failed to get file from request: %v", err)
		return response.BadRequest(c, "Failed to get file from request", err)
	}
	log.Printf("Temp file: %+v", fileHeader)

	// Get batch_id from form data
	batchID := c.FormValue("batch_id")
	if batchID == "" {
		log.Printf("[MOBSF] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	log.Printf("[MOBSF] Validating batch ownership for batch_id=%s", batchID)
	if err := h.batchService.ValidateBatchOwnership(c, batchID); err != nil {
		log.Printf("[MOBSF] Batch ownership validation failed: %v", err)
		return err
	}

	// Open the uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		log.Printf("[MOBSF] Failed to open uploaded file: %v", err)
		return response.InternalServerError(c, "Failed to open uploaded file", err)
	}
	defer file.Close()

	log.Printf("[MOBSF] Starting upload for file=%s", fileHeader.Filename)
	
	// Create uploaded file record via LifecycleService
	// Note: We need to pass a reader that we can read. `file` is already open.
	// But `Upload` in lifecycle expects to read fully.
	// Also we need to calculate hash separately if Lifecycle doesn't do it?
	// Actually `LifecycleService.Upload` saves it to disk.
	// Check `LifecycleService.Upload` signature: (batchID string, fileName string, file io.Reader, size int64, hash string)
	// Wait, I implemented `Upload(batchID string, fileName string, file io.Reader, size int64, hash string)`?
	// Let me double check my implementation of lifecycle.go in step 50.
	// "func (s *LifecycleService) Upload(batchID string, fileName string, file io.Reader, size int64, hash string) ..."
	// No, step 50 implementation was:
	// func (s *LifecycleService) Upload(batchID string, fileName string, file io.Reader, size int64, hash string) ...
	// Wait, I should verify the implementation from step 50/51.
	// Ah, I see "func (s *LifecycleService) Upload(batchID string, fileName string, file io.Reader, size int64, hash string)" in my thought but let me check the file content I wrote.
	// It was: "Upload(batchID string, fileName string, file io.Reader, size int64, hash string)" ... wait, line 40 of step 50 output says:
	// "func (s *LifecycleService) Upload(batchID string, fileName string, file io.Reader, size int64, hash string) (*models.UploadedFile, error) {"
	// YES.
	
	// So I need to calculate hash first?
	// MobSF usually calculates hash.
	// But LifecycleService needs it for path: /data/uploads/{batch_id}/{hash}.{ext}
	// So I MUST calculate hash before calling lifecycle.Upload.
	// `file` is `multipart.File`.
	
	// We need to read file to calculate hash, then seek back to 0.
	// Or use tee reader? But we need hash for filename.
	// So: Read all -> Hash -> Seek 0 -> Pass to Lifecycle.
	
	// Helper to calc hash
	hash, err := calculateHash(file)
	if err != nil {
		log.Printf("[MOBSF] Failed to calculate hash: %v", err)
		return response.InternalServerError(c, "Failed to calculate file hash", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		log.Printf("[MOBSF] Failed to seek file: %v", err)
		return response.InternalServerError(c, "Failed to reset file pointer", err)
	}
	
	uploadedFile, err := h.lifecycle.Upload(batchID, fileHeader.Filename, file, fileHeader.Size, hash)
	if err != nil {
		log.Printf("[MOBSF] Lifecycle Upload failed: %v", err)
		return response.InternalServerError(c, "Failed to process upload", err)
	}
	
	log.Printf("[MOBSF] Lifecycle Upload completed, id=%d hash=%s", uploadedFile.ID, uploadedFile.Hash)
	
	// Trigger MobSF Scan Async
	h.lifecycle.StartMobSF(uploadedFile.ID)

	payload := fiber.Map{
		"hash":      uploadedFile.Hash,
		"file_name": uploadedFile.FileName,
		"batch_id":  batchID,
		"file_id":   uploadedFile.ID,
		"status":    models.FileStatusMobSFRunning,
	}

	log.Printf("[MOBSF] Upload request completed successfully")
	return response.Success(c, "File uploaded and scan started", payload)
}

func calculateHash(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
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
	log.Printf("[MOBSF] Received scan request")
	var req models.MobSFScanRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[MOBSF] Failed to parse request body: %v", err)
		return response.BadRequest(c, "Invalid request payload", err)
	}

	if req.BatchID == "" {
		log.Printf("[MOBSF] Missing batch_id")
		return response.BadRequest(c, "batch_id is required", nil)
	}

	// Enforce batch ownership
	log.Printf("[MOBSF] Validating batch ownership for batch_id=%s", req.BatchID)
	if err := h.batchService.ValidateBatchOwnership(c, req.BatchID); err != nil {
		log.Printf("[MOBSF] Batch ownership validation failed: %v", err)
		return err
	}

	hash := strings.TrimSpace(req.Hash)
	if hash == "" {
		log.Printf("[MOBSF] Missing hash")
		return response.BadRequest(c, "hash is required", nil)
	}
	if err := validateMobSFHash(hash); err != nil {
		log.Printf("[MOBSF] Invalid hash: %v", err)
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

	log.Printf("[MOBSF] Starting scan for hash=%s", info.Hash)
	scanRaw, err := mobsf.Scan(ctx, info)
	if err != nil {
		if isMobSFDebug() {
			log.Printf("[mobsf] scan error: %v", err)
		}
		log.Printf("[MOBSF] Scan failed: %v", err)
		return response.Error(c, fiber.StatusBadGateway, "MobSF scan failed", err.Error())
	}
	log.Printf("[MOBSF] Scan completed, fetching report...")

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
		log.Printf("[MOBSF] Failed to get report: %v", lastErr)
		return response.Error(c, fiber.StatusBadGateway, "MobSF report_json failed", lastErr.Error())
	}
	log.Printf("[MOBSF] Report retrieved successfully")

	compact := isTruthy(c.Query("compact"))
	if compact {
		log.Printf("[MOBSF] Building compact summary")
		summary := service.BuildMobSFSummary(info, scanRaw, reportRaw)
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
				log.Printf("[MOBSF] Failed to save to database: %v", dbErr)
				return response.InternalServerError(c, "Failed to save scan result", dbErr)
			}
			log.Printf("[MOBSF] Database insert success")
		}

		log.Printf("[MOBSF] Compact scan request completed successfully")
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
			log.Printf("[MOBSF] Failed to save to database: %v", dbErr)
			return response.InternalServerError(c, "Failed to save scan result", dbErr)
		}
		log.Printf("[MOBSF] Database insert success")
	}

	log.Printf("[MOBSF] Full scan request completed successfully")
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

// buildMobSFSummary removed (moved to service.BuildMobSFSummary)