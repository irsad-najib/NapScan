package service

import (
	"log"
	"napscan-be/internal/models"
	"time"

	"gorm.io/gorm"
)

type AgentService struct {
	DB            *gorm.DB
	RiskService   *RiskService
	ReportService *ReportService
	Ticker        *time.Ticker
	Done          chan bool
}

func NewAgentService(db *gorm.DB, risk *RiskService, report *ReportService) *AgentService {
	return &AgentService{
		DB:            db,
		RiskService:   risk,
		ReportService: report,
		Ticker:        time.NewTicker(30 * time.Second), // Check every 30 seconds
		Done:          make(chan bool),
	}
}

// Start begins the monitoring loop
func (s *AgentService) Start() {
	go func() {
		for {
			select {
			case <-s.Done:
				return
			case <-s.Ticker.C:
				s.processCompletedBatches()
			}
		}
	}()
	log.Println("Security Report Agent started...")
}

func (s *AgentService) Stop() {
	s.Ticker.Stop()
	s.Done <- true
	log.Println("Security Report Agent stopped.")
}

func (s *AgentService) processCompletedBatches() {
	var batches []models.Batch

	// Find batches that are 'complete' but have no report_path yet
	// Assuming 'complete' status means all scans are done
	err := s.DB.Where("status = ? AND (report_path IS NULL OR report_path = '')", models.BatchStatusComplete).Find(&batches).Error
	if err != nil {
		log.Printf("Error processing batches: %v", err)
		return
	}

	for _, batch := range batches {
		log.Printf("Generating report for Batch %s...", batch.BatchID)
		
		// 1. Analyze and Risk Score
		reportData, err := s.RiskService.AnalyzeBatch(batch.BatchID)
		if err != nil {
			log.Printf("Failed to analyze batch %s: %v", batch.BatchID, err)
			continue
		}

		// 2. Generate PDF
		path, err := s.ReportService.GeneratePDF(reportData)
		if err != nil {
			log.Printf("Failed to generate PDF for batch %s: %v", batch.BatchID, err)
			continue
		}

		// 3. Update Batch with Report Path
		batch.ReportPath = path
		if err := s.DB.Save(&batch).Error; err != nil {
			log.Printf("Failed to update batch %s with report path: %v", batch.BatchID, err)
		} else {
			log.Printf("Report generated successfully for batch %s: %s", batch.BatchID, path)
		}
	}
}
