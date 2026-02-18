package service

import (
	"context"
	"fmt"
	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"napscan-be/pkg/logger"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

type SchedulerService struct {
	repo          repository.ScheduleRepository
	cron          *cron.Cron
	jobs          map[string]cron.EntryID
	mu            sync.RWMutex
	batchService  *BatchService
	scanManager   *ScanManager
	scanRepo      repository.ScanResultRepository
	lifecycle     *LifecycleService
	nucleiService *NucleiService
	intelligence  *IntelligenceService
}

func NewSchedulerService(
	repo repository.ScheduleRepository,
	batchService *BatchService,
	scanManager *ScanManager,
	scanRepo repository.ScanResultRepository,
	lifecycle *LifecycleService,
	nucleiService *NucleiService,
	intelligence *IntelligenceService,
) *SchedulerService {
	return &SchedulerService{
		repo:          repo,
		cron:          cron.New(),
		jobs:          make(map[string]cron.EntryID),
		batchService:  batchService,
		scanManager:   scanManager,
		scanRepo:      scanRepo,
		lifecycle:     lifecycle,
		nucleiService: nucleiService,
		intelligence:  intelligence,
	}
}

func (s *SchedulerService) Start() {
	s.cron.Start()
	schedules, err := s.repo.FindActive()
	if err != nil {
		logger.Error("[SCHEDULER] Failed to load schedules: %v", err)
		return
	}

	for _, sch := range schedules {
		if err := s.AddJob(&sch); err != nil {
			logger.Error("[SCHEDULER] Failed to add job for schedule %s: %v", sch.ID, err)
		}
	}
	logger.Info("[SCHEDULER] Started with %d active jobs", len(schedules))
}

func (s *SchedulerService) Stop() {
	s.cron.Stop()
}

func (s *SchedulerService) Create(schedule *models.Schedule) error {
	if err := s.repo.Create(schedule); err != nil {
		return err
	}
	if schedule.IsActive {
		return s.AddJob(schedule)
	}
	return nil
}

func (s *SchedulerService) AddJob(schedule *models.Schedule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entryID, exists := s.jobs[schedule.ID]; exists {
		s.cron.Remove(entryID)
	}

	entryID, err := s.cron.AddFunc(schedule.CronExpression, func() {
		s.TriggerScan(schedule.ID)
	})
	if err != nil {
		return err
	}

	s.jobs[schedule.ID] = entryID
	logger.Info("[SCHEDULER] Added job for schedule %s (cron: %s)", schedule.ID, schedule.CronExpression)
	return nil
}

func (s *SchedulerService) RemoveJob(scheduleID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entryID, exists := s.jobs[scheduleID]; exists {
		s.cron.Remove(entryID)
		delete(s.jobs, scheduleID)
	}
}

func (s *SchedulerService) Pause(id, userID string) error {
	schedule, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	if schedule.UserID != userID {
		return fmt.Errorf("unauthorized: schedule does not belong to user")
	}

	schedule.IsActive = false
	if err := s.repo.Update(schedule); err != nil {
		return err
	}
	s.RemoveJob(id)
	return nil
}

func (s *SchedulerService) Resume(id, userID string) error {
	schedule, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	if schedule.UserID != userID {
		return fmt.Errorf("unauthorized: schedule does not belong to user")
	}

	schedule.IsActive = true
	if err := s.repo.Update(schedule); err != nil {
		return err
	}
	return s.AddJob(schedule)
}

func (s *SchedulerService) Delete(id, userID string) error {
	schedule, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	if schedule.UserID != userID {
		return fmt.Errorf("unauthorized: schedule does not belong to user")
	}

	s.RemoveJob(id)
	return s.repo.Delete(id)
}

func (s *SchedulerService) List(userID string) ([]models.Schedule, error) {
	return s.repo.FindByUserID(userID)
}

func (s *SchedulerService) TriggerScan(scheduleID string) {
	logger.Info("[SCHEDULER] Triggering scan for schedule %s", scheduleID)
	sch, err := s.repo.FindByID(scheduleID)
	if err != nil {
		logger.Error("[SCHEDULER] Failed to find schedule %s: %v", scheduleID, err)
		return
	}

	// 1. Create Batch for this run
	batchID, err := s.batchService.CreateBatch(context.Background(), sch.UserID)
	if err != nil {
		logger.Error("[SCHEDULER] Failed to create batch for schedule %s: %v", scheduleID, err)
		return
	}

	// Update Schedule to "Running"
	now := time.Now()
	sch.LastRun = &now
	sch.LastRunStatus = "running"

	if entryID, ok := s.jobs[scheduleID]; ok {
		entry := s.cron.Entry(entryID)
		next := entry.Next
		sch.NextRun = &next
	}
	s.repo.Update(sch)

	// 4. Run Async for each tool
	tools := strings.Split(sch.Tool, ",")
	// Trim spaces and filter empty
	var validTools []string
	for _, t := range tools {
		t = strings.TrimSpace(t)
		if t != "" {
			validTools = append(validTools, t)
		}
	}

	for _, tool := range validTools {
		// Create Task for each tool
		scanTaskID := uuid.New().String()

		// We need to register task in ScanManager
		taskCtx, taskCancel := context.WithCancel(context.Background())

		task := &models.ScanTask{
			BatchID:   batchID,
			TaskID:    scanTaskID,
			UserID:    sch.UserID,
			Target:    sch.Target,
			Tool:      tool,
			Status:    models.StatusPending,
			Progress:  0,
			Error:     nil,
			Result:    []map[string]interface{}{},
			StartedAt: time.Now(),
			UpdatedAt: time.Now(),
			Cancel:    taskCancel,
		}
		s.scanManager.Register(task)

		// Update LastResourceID to the latest task
		sch.LastResourceID = scanTaskID
		s.repo.Update(sch)

		go func(t string, tID string, ctx context.Context) {
			var err error
			logger.Info("[SCHEDULER] Starting tool %s for schedule %s (task %s)", t, scheduleID, tID)

			switch t {
			case "nmap":
				err = RunNmapAsync(ctx, tID, s.scanManager)
			case "zap":
				err = RunZapAsync(ctx, tID, s.scanManager)
			case "nuclei":
				// Use instance method now
				err = s.nucleiService.RunNucleiAsync(ctx, tID, s.scanManager, sch.UserID)
			case "ffuf":
				err = RunFfufAsync(ctx, tID, s.scanManager)
			case "sslyze":
				err = RunSslyzeAsync(ctx, tID, s.scanManager)
			case "openvas":
				openvasSvc := NewOpenVASService()
				err = RunOpenVASAsync(ctx, tID, s.scanManager, openvasSvc)
			case "apk", "mobsf":
				// Handle APK scan via LifecycleService
				fileID, parseErr := itemToInt(sch.Target)
				if parseErr != nil {
					err = fmt.Errorf("invalid target for apk scan (expected fileID): %v", parseErr)
				} else {
					err = s.lifecycle.StartMobSF(uint(fileID), sch.Decision)
				}
			default:
				err = fmt.Errorf("unknown tool: %s", t)
			}

			if err != nil {
				logger.Error("[SCHEDULER] Scan failed for tool %s schedule %s: %v", t, scheduleID, err)
			} else {
				// Process Intelligence and Save to DB
				if task, _ := s.scanManager.Get(tID); task != nil && task.Status == models.StatusCompleted {
					dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer dbCancel()

					// Intelligence Processing
					if s.intelligence != nil {
						// For APK scans, result might be complex, but ProcessScanResult delegating to parser handles it.
						// Parser implementations (mobsf, etc) should be robust.
						if intelErr := s.intelligence.ProcessScanResult(dbCtx, batchID, sch.UserID, t, task.Result); intelErr != nil {
							logger.Warn("[SCHEDULER] Intelligence processing warning for %s: %v", t, intelErr)
						}
					}

					_, dbErr := s.scanRepo.Insert(dbCtx, &models.ScanResult{
						BatchID:   task.BatchID,
						Tool:      t,
						Target:    task.Target,
						Result:    task.Result,
						CreatedAt: time.Now().UTC(),
					})
					if dbErr != nil {
						logger.Error("[SCHEDULER] Failed to save result: %v", dbErr)
					}
				}
			}
		}(tool, scanTaskID, taskCtx)
	}

	// Update Schedule Status to "success" (launched)
	sch.LastRunStatus = "success"
	s.repo.Update(sch)
}
