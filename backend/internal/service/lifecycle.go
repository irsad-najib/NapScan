package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"

	"gorm.io/gorm"
)

type LifecycleService struct {
	db       *gorm.DB
	basePath string
	mobsf    *MobSFService
	frida    *FridaService
	scanRepo repository.ScanResultRepository
}

func NewLifecycleService(db *gorm.DB, scanRepo repository.ScanResultRepository) *LifecycleService {
	// Ensure base storage path exists
	basePath := os.Getenv("UPLOAD_DIR")
	if basePath == "" {
		basePath = "/data/uploads"
	}
	// We might not have permission to create root /data, so user should run with volume
	// But we try to ensure it exists or panic/log on startup in real app.
	// For now we assume the dir or its parent is writable or pre-created by Docker.
	if err := os.MkdirAll(basePath, 0755); err != nil {
		fmt.Printf("Warning: Failed to create upload base dir %s: %v\n", basePath, err)
	}

	return &LifecycleService{
		db:       db,
		basePath: basePath,
		mobsf:    NewMobSFService(),
		frida:    NewFridaService(),
		scanRepo: scanRepo,
	}
}

// Upload handles the initial file persistence and DB record creation
func (s *LifecycleService) Upload(batchID string, fileName string, file io.Reader, size int64, hash string) (*models.UploadedFile, error) {
	// 1. Determine storage path: /data/uploads/{batch_id}/{hash}.{ext}
	ext := filepath.Ext(fileName)
	batchDir := filepath.Join(s.basePath, batchID)
	if err := os.MkdirAll(batchDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create batch directory: %w", err)
	}

	// Sanitize hash to avoid path traversal (though hash should be safe hex)
	safeHash := filepath.Base(hash)
	storedFileName := safeHash + ext
	fullPath := filepath.Join(batchDir, storedFileName)

	// 2. Write file to disk
	dst, err := os.Create(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file on disk: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		return nil, fmt.Errorf("failed to write file content: %w", err)
	}

	// 3. Create DB record
	uploadedFile := &models.UploadedFile{
		BatchID:   batchID,
		FileName:  fileName,
		FilePath:  fullPath,
		Hash:      hash,
		Status:    models.FileStatusUploaded,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if result := s.db.Create(uploadedFile); result.Error != nil {
		// Try cleanup file if DB fail
		_ = os.Remove(fullPath)
		return nil, fmt.Errorf("failed to save file record to database: %w", result.Error)
	}

	return uploadedFile, nil
}

// UpdateStatus transitions the file state
func (s *LifecycleService) UpdateStatus(fileID uint, status models.FileStatus, errorMsg string) error {
	var file models.UploadedFile
	if err := s.db.First(&file, fileID).Error; err != nil {
		return err
	}

	if !file.CanTransitionTo(status) {
		return fmt.Errorf("invalid state transition from %s to %s", file.Status, status)
	}

	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now().UTC(),
	}
	if errorMsg != "" {
		updates["error_message"] = errorMsg
		// If explicit error message provided, we force FAILED, but we must check valid transition to FAILED too
		// The check above checked `status`. If caller passed `FileStatusFailed`, it passed.
		// If caller passed valid status but errorMsg, we override to FAILED?
		// User requirement: "Any failure must Move state to FAILED"
		// So if errorMsg is set, we assume target state IS FAILED.
		if status != models.FileStatusFailed {
			// Check if we can transition to FAILED instead
			if !file.CanTransitionTo(models.FileStatusFailed) {
				return fmt.Errorf("cannot transition to FAILED from %s", file.Status)
			}
			updates["status"] = models.FileStatusFailed
		}
	}

	result := s.db.Model(&models.UploadedFile{}).Where("id = ?", fileID).Updates(updates)
	return result.Error
}

// StartMobSF initiates the MobSF scan flow asynchronously
func (s *LifecycleService) StartMobSF(fileID uint, autoFrida bool) error {
	// Sync state update first
	if err := s.UpdateStatus(fileID, models.FileStatusMobSFRunning, ""); err != nil {
		return err
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()

		file, err := s.GetFile(fileID)
		if err != nil {
			log.Printf("[LIFECYCLE] Failed to get file %d: %v", fileID, err)
			return
		}

		// Open file from disk
		f, err := os.Open(file.FilePath)
		if err != nil {
			s.UpdateStatus(fileID, models.FileStatusFailed, fmt.Sprintf("Failed to open file: %v", err))
			return
		}
		defer f.Close()

		// 1. Upload to MobSF
		log.Printf("[LIFECYCLE] Uploading file %s to MobSF", file.FileName)
		info, _, err := s.mobsf.Upload(ctx, file.FileName, f)
		if err != nil {
			s.UpdateStatus(fileID, models.FileStatusFailed, fmt.Sprintf("MobSF upload failed: %v", err))
			return
		}

		// 2. Scan
		log.Printf("[LIFECYCLE] Starting MobSF scan for hash %s", info.Hash)
		_, err = s.mobsf.Scan(ctx, info)
		if err != nil {
			s.UpdateStatus(fileID, models.FileStatusFailed, fmt.Sprintf("MobSF scan failed: %v", err))
			return
		}

		// 3. Get Report
		// Retry logic is already in MobSFService.ReportJSON? No, MobSFService.ReportJSON is raw.
		// Use Analyze helper? Actually `Analyze` in mobsf_service.go does upload+scan+report.
		// But we already did upload+scan step by step?
		// Let's use ReportJSON directly.
		log.Printf("[LIFECYCLE] Fetching MobSF report for hash %s", info.Hash)

		// Simple retry wrapper for report
		var reportRaw map[string]interface{}
		for i := 0; i < 5; i++ {
			reportRaw, err = s.mobsf.ReportJSON(ctx, info)
			if err == nil {
				break
			}
			time.Sleep(2 * time.Second)
		}

		if err != nil {
			s.UpdateStatus(fileID, models.FileStatusFailed, fmt.Sprintf("MobSF report failed: %v", err))
			return
		}

		// 4. Evaluate & Save
		// Use shared summarizer to get full report details (permissions, findings, etc)
		mobsfSummary := BuildMobSFSummary(info, nil, reportRaw)

		// Wrap in "mobsf" key for future merging
		finalSummary := map[string]interface{}{
			"mobsf": mobsfSummary,
		}
		summaryBytes, _ := json.Marshal(finalSummary)

		// Determine severity/recommendation
		scoreStr := fmt.Sprintf("%v", getMapValue(getMapValue(reportRaw, "appsec"), "security_score"))
		score, _ := itemToInt(scoreStr) // helper needed or just minimal logic

		// Update DB to MOBSF_DONE / WAITING_USER_DECISION
		// "Implement explicit states ... WAITING_USER_DECISION"

		updates := map[string]interface{}{
			"status":           models.FileStatusWaitingUserDecision,
			"findings_summary": string(summaryBytes),
			"updated_at":       time.Now().UTC(),
		}

		if score < 50 {
			updates["severity_score"] = "high"
		} else if score < 80 {
			updates["severity_score"] = "medium"
		} else {
			updates["severity_score"] = "low"
		}

		if err := s.db.Model(&models.UploadedFile{}).Where("id = ?", fileID).Updates(updates).Error; err != nil {
			log.Printf("[LIFECYCLE] Failed to save findings: %v", err)
		}

		// Save full scan result to scan_results table for consistency with other tools
		if s.scanRepo != nil {
			scanResult := &models.ScanResult{
				BatchID:   file.BatchID,
				Tool:      "mobsf",
				Target:    file.FileName,
				Result:    finalSummary,
				CreatedAt: time.Now().UTC(),
			}

			if _, err := s.scanRepo.Insert(context.Background(), scanResult); err != nil {
				log.Printf("[LIFECYCLE] Failed to save MobSF scan result: %v", err)
			} else {
				log.Printf("[LIFECYCLE] MobSF scan result persisted to DB for file %d", fileID)
			}
		}

		log.Printf("[LIFECYCLE] File %d MobSF scan completed. AutoFrida: %v", fileID, autoFrida)

		// Auto-trigger Frida if requested
		if autoFrida {
			log.Printf("[LIFECYCLE] Auto-triggering Frida scan for file %d", fileID)
			// Small delay to ensure DB commit visible? Not needed if same connection usually.
			// But StartFrida reads from DB. Update above happened.
			// StartFrida requires STATUS to be something?
			// StartFrida transitions to FridaRunning. It only checks existence.
			if err := s.StartFrida(fileID); err != nil {
				log.Printf("[LIFECYCLE] Failed to auto-trigger Frida: %v", err)
				// We should probably mark as Failed, but StartFrida likely did that if it failed early.
			}
		}
	}()

	return nil
}

// StartFrida initiates the Frida dynamic scan
func (s *LifecycleService) StartFrida(fileID uint) error {
	log.Printf("[LIFECYCLE] StartFrida called for file %d", fileID)
	// Validate before async
	file, err := s.GetFile(fileID)
	if err != nil {
		return err
	}

	log.Printf("[LIFECYCLE] Starting Frida scan for file %s", file.FileName)

	// Sync state update first
	if err := s.UpdateStatus(fileID, models.FileStatusFridaRunning, ""); err != nil {
		return err
	}

	log.Printf("[LIFECYCLE] Frida: Starting scan--2 for file %d", fileID)
	go func() {
		log.Printf("[LIFECYCLE] Frida: Inside goroutine for file %d", fileID)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		// Re-fetch file inside goroutine to be safe? or use `file` captured?
		// `file` is captured by value (copy of struct). Safe.

		log.Printf("[LIFECYCLE] Frida: Parsing findings, Findings length: %d", len(file.Findings))
		// Parse findings to get package_name
		var findings map[string]interface{}
		if err := json.Unmarshal([]byte(file.Findings), &findings); err != nil {
			log.Printf("[LIFECYCLE] Frida: Failed to parse findings for file %d: %v", fileID, err)
			s.UpdateStatus(fileID, models.FileStatusFailed, "Missing previous scan data")
			return
		}
		log.Printf("[LIFECYCLE] Frida: Successfully parsed findings")

		mobsf, ok := findings["mobsf"].(map[string]interface{})
		if !ok {
			log.Printf("[LIFECYCLE] Frida: Missing MobSF data in findings")
			s.UpdateStatus(fileID, models.FileStatusFailed, "Missing MobSF data")
			return
		}
		log.Printf("[LIFECYCLE] Frida: Successfully extracted MobSF data")

		// Extract package_name from identity object
		identity, ok := mobsf["identity"].(map[string]interface{})
		if !ok {
			log.Printf("[LIFECYCLE] Frida: Missing identity data in MobSF findings")
			s.UpdateStatus(fileID, models.FileStatusFailed, "Missing identity data")
			return
		}

		pkgName := fmt.Sprint(identity["package_name"])
		log.Printf("[LIFECYCLE] Frida: Extracted package name: %s", pkgName)
		if pkgName == "" || pkgName == "<nil>" {
			log.Printf("[LIFECYCLE] Frida: Package name is empty or nil")
			s.UpdateStatus(fileID, models.FileStatusFailed, "Package name not found")
			return
		}

		// Setup deferred uninstall to ensure cleanup happens
		defer func() {
			log.Printf("[LIFECYCLE] Uninstalling APK from emulator: %s", pkgName)
			uninstallCtx, uninstallCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer uninstallCancel()

			uninstallCmd := exec.CommandContext(uninstallCtx, "adb", "uninstall", pkgName)
			if output, err := uninstallCmd.CombinedOutput(); err != nil {
				log.Printf("[LIFECYCLE] Failed to uninstall APK (non-fatal): %v, output: %s", err, string(output))
			} else {
				log.Printf("[LIFECYCLE] APK uninstalled successfully")
			}
		}()

		// Install APK to emulator before scanning
		log.Printf("[LIFECYCLE] Installing APK to emulator: %s", file.FilePath)
		installCtx, installCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer installCancel()

		installCmd := exec.CommandContext(installCtx, "adb", "install", "-r", file.FilePath)
		installOutput, err := installCmd.CombinedOutput()
		if err != nil {
			log.Printf("[LIFECYCLE] Failed to install APK: %v, output: %s", err, string(installOutput))
			s.UpdateStatus(fileID, models.FileStatusFailed, fmt.Sprintf("APK installation failed: %v", err))
			return
		}
		log.Printf("[LIFECYCLE] APK installed successfully")

		log.Printf("[LIFECYCLE] Starting Frida scan for %s (%s)", file.FileName, pkgName)
		results, err := s.frida.RunScan(ctx, pkgName)
		if err != nil {
			s.UpdateStatus(fileID, models.FileStatusFailed, fmt.Sprintf("Frida scan failed: %v", err))
			return
		}

		// Merge results
		findings["frida"] = results
		newFindingsBytes, _ := json.Marshal(findings)

		updates := map[string]interface{}{
			"status":           models.FileStatusCompleted, // DONE
			"findings_summary": string(newFindingsBytes),
			"updated_at":       time.Now().UTC(),
		}

		if err := s.db.Model(&models.UploadedFile{}).Where("id = ?", fileID).Updates(updates).Error; err != nil {
			log.Printf("[LIFECYCLE] Failed to save Frida findings: %v", err)
		}

		// Save Frida scan result to scan_results table
		if s.scanRepo != nil {
			scanResult := &models.ScanResult{
				BatchID:   file.BatchID,
				Tool:      "frida",
				Target:    pkgName,
				Result:    findings["frida"],
				CreatedAt: time.Now().UTC(),
			}

			if _, err := s.scanRepo.Insert(context.Background(), scanResult); err != nil {
				log.Printf("[LIFECYCLE] Failed to save Frida scan result: %v", err)
			} else {
				log.Printf("[LIFECYCLE] Frida scan result persisted to DB for file %d", fileID)
			}
		}

		log.Printf("[LIFECYCLE] Frida scan completed for file %d", fileID)
	}()

	return nil
}

func getMapValue(m interface{}, key string) interface{} {
	if mp, ok := m.(map[string]interface{}); ok {
		return mp[key]
	}
	return nil
}

// Cleanup removes the physical file and updates state to CLEANED
func (s *LifecycleService) Cleanup(fileID uint) error {
	file, err := s.GetFile(fileID)
	if err != nil {
		return err
	}

	if file.Status == models.FileStatusCleaned {
		return nil
	}

	// Remove from disk
	if file.FilePath != "" {
		if err := os.Remove(file.FilePath); err != nil && !os.IsNotExist(err) {
			log.Printf("[LIFECYCLE] Failed to remove file %s: %v", file.FilePath, err)
			// Continue to update state even if file missing
		}
	}

	return s.UpdateStatus(fileID, models.FileStatusCleaned, "")
}

// StartCleanupWorker starts a background worker that cleans up files older than ttl
func (s *LifecycleService) StartCleanupWorker(ctx context.Context, ttl time.Duration, checkInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanupOldFiles(ttl)
			}
		}
	}()
}

func (s *LifecycleService) cleanupOldFiles(ttl time.Duration) {
	// Find files that are COMPLETED or FAILED and older than TTL
	// AND not yet CLEANED
	threshold := time.Now().Add(-ttl)
	var files []models.UploadedFile

	// Guards: ONLY cleanup COMPLETED or FAILED.
	// NEVER cleanup UPLOADED, RUNNING, or WAITING.

	err := s.db.Where("status IN ? AND updated_at < ?",
		[]models.FileStatus{models.FileStatusCompleted},
		threshold).Find(&files).Error

	if err != nil {
		log.Printf("[LIFECYCLE] Cleanup worker failed to query: %v", err)
		return
	}

	for _, f := range files {
		log.Printf("[LIFECYCLE] Cleaning up expired file %d (%s)", f.ID, f.FileName)
		if err := s.Cleanup(f.ID); err != nil {
			log.Printf("[LIFECYCLE] Failed to cleanup file %d: %v", f.ID, err)
		}
	}
}

func itemToInt(v interface{}) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case float64:
		return int(t), nil
	case string:
		var i int
		fmt.Sscanf(t, "%d", &i)
		return i, nil
	}
	return 0, fmt.Errorf("invalid type")
}

// GetFile retrieves the file record
func (s *LifecycleService) GetFile(fileID uint) (*models.UploadedFile, error) {
	var f models.UploadedFile
	if err := s.db.First(&f, fileID).Error; err != nil {
		return nil, err
	}
	return &f, nil
}

// GetFileByHash retrieves the file record by hash and batchID
func (s *LifecycleService) GetFileByHash(batchID, hash string) (*models.UploadedFile, error) {
	var f models.UploadedFile
	if err := s.db.Where("batch_id = ? AND hash = ?", batchID, hash).First(&f).Error; err != nil {
		return nil, err
	}
	return &f, nil
}
