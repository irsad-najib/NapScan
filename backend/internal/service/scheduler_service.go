package service

import (
	"context"
	"fmt"
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/repository"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

type SchedulerService struct {
	repo         repository.ScheduleRepository
	cron         *cron.Cron
	jobs         map[string]cron.EntryID
	mu           sync.RWMutex
	batchService *BatchService // Same package
	scanManager  *ScanManager  // Same package
	scanRepo     repository.ScanResultRepository
}

func NewSchedulerService(
	repo repository.ScheduleRepository,
	batchService *BatchService,
	scanManager *ScanManager,
	scanRepo repository.ScanResultRepository,
) *SchedulerService {
	return &SchedulerService{
		repo:         repo,
		cron:         cron.New(),
		jobs:         make(map[string]cron.EntryID),
		batchService: batchService,
		scanManager:  scanManager,
		scanRepo:     scanRepo,
	}
}

func (s *SchedulerService) Start() {
	s.cron.Start()
	// Load active schedules
	schedules, err := s.repo.FindActive()
	if err != nil {
		log.Printf("[SCHEDULER] Failed to load schedules: %v", err)
		return
	}

	for _, sch := range schedules {
		if err := s.AddJob(&sch); err != nil {
			log.Printf("[SCHEDULER] Failed to add job for schedule %s: %v", sch.ID, err)
		}
	}
	log.Printf("[SCHEDULER] Started with %d active jobs", len(schedules))
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

	// Remove existing if any
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
	log.Printf("[SCHEDULER] Added job for schedule %s (cron: %s)", schedule.ID, schedule.CronExpression)
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

func (s *SchedulerService) Pause(id string) error {
	schedule, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	schedule.IsActive = false
	if err := s.repo.Update(schedule); err != nil {
		return err
	}
	s.RemoveJob(id)
	return nil
}

func (s *SchedulerService) Resume(id string) error {
	schedule, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	schedule.IsActive = true
	if err := s.repo.Update(schedule); err != nil {
		return err
	}
	return s.AddJob(schedule)
}

func (s *SchedulerService) Delete(id string) error {
	s.RemoveJob(id)
	return s.repo.Delete(id)
}

func (s *SchedulerService) List() ([]models.Schedule, error) {
	return s.repo.FindAll()
}

func (s *SchedulerService) TriggerScan(scheduleID string) {
	log.Printf("[SCHEDULER] Triggering scan for schedule %s", scheduleID)
	sch, err := s.repo.FindByID(scheduleID)
	if err != nil {
		log.Printf("[SCHEDULER] Failed to find schedule %s: %v", scheduleID, err)
		return
	}

	// 1. Create Batch for this run
	batchID, err := s.batchService.CreateBatch(context.Background(), sch.UserID)
	if err != nil {
		log.Printf("[SCHEDULER] Failed to create batch for schedule %s: %v", scheduleID, err)
		return
	}

	// Optional: You might want to update the batch with target/tool info immediately
	// but currently CreateBatch only takes userID. The scan results will link to it.

	// 2. Create Task
	taskID := uuid.New().String()
	// Update Schedule to "Running"
	now := time.Now()
	sch.LastRun = &now
	sch.LastRunStatus = "running"
	sch.LastResourceID = taskID
	// sch.NextRun = ??? Cron parser can tell next run? Cron library entry has Next.
	// I can get it from cron.Entry(id).Next
	if entryID, ok := s.jobs[scheduleID]; ok {
		entry := s.cron.Entry(entryID)
		next := entry.Next
		sch.NextRun = &next
	}
	s.repo.Update(sch)

	// 3. Register Task
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx) // leaks? Need to manage cancellation. task.Cancel handles it.

	task := &models.ScanTask{
		BatchID:   batchID,
		TaskID:    taskID,
		UserID:    sch.UserID,
		Target:    sch.Target,
		Tool:      sch.Tool, // Populate Tool
		Status:    models.StatusPending,
		Progress:  0,
		Error:     nil,
		Result:    []map[string]interface{}{},
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Cancel:    cancel,
	}
	s.scanManager.Register(task)

	// 4. Run Async
	go func() {
		var err error
		switch sch.Tool {
		case "nmap":
			err = RunNmapAsync(ctx, taskID, s.scanManager)
		case "zap":
			err = RunZapAsync(ctx, taskID, s.scanManager)
		case "nuclei":
			err = RunNucleiAsync(ctx, taskID, s.scanManager)
		case "ffuf":
			err = RunFfufAsync(ctx, taskID, s.scanManager)
		case "sslyze":
			err = RunSslyzeAsync(ctx, taskID, s.scanManager)
		default:
			err = fmt.Errorf("unknown tool: %s", sch.Tool)
		}

		// Update Schedule Status
		status := "success"
		if err != nil {
			status = "failed"
			log.Printf("[SCHEDULER] Scan failed for schedule %s: %v", scheduleID, err)
		} else {

			// Save to DB (ScanResult)
			// StartScanAsync handler does this. I must duplicate it here.
			if task, _ := s.scanManager.Get(taskID); task != nil && task.Status == models.StatusCompleted {
				dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer dbCancel()
				_, dbErr := s.scanRepo.Insert(dbCtx, &models.ScanResult{
					BatchID:   task.BatchID,
					Tool:      sch.Tool,
					Target:    task.Target,
					Result:    task.Result,
					CreatedAt: time.Now().UTC(),
				})
				if dbErr != nil {
					log.Printf("[SCHEDULER] Failed to save result: %v", dbErr)
					status = "failed_save"
				}
			}
		}

		sch.LastRunStatus = status
		s.repo.Update(sch)
	}()
}
