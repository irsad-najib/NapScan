package service

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"napscan-be/internal/models"
)

// SafeBatch wraps the Batch model with a mutex for thread safety
type SafeBatch struct {
	mu              sync.Mutex
	Batch           *models.Batch
	analysisStarted bool
}

type BatchService struct {
	// batches stores pointers to SafeBatch, key is batchID
	batches sync.Map
}

var (
	batchServiceInstance *BatchService
	batchServiceOnce     sync.Once
)

func NewBatchService() *BatchService {
	batchServiceOnce.Do(func() {
		batchServiceInstance = &BatchService{}
	})
	return batchServiceInstance
}

// AddResult contributes a result to a batch.
// If valid and complete, triggers analysis.
func (s *BatchService) AddResult(userID, batchID string, source string, data interface{}) error {
	// 1. Get or Create Batch
	val, _ := s.batches.LoadOrStore(batchID, &SafeBatch{
		Batch: &models.Batch{
			UserID:        userID,
			BatchID:       batchID,
			ExpectedCount: 5, // Hardcoded requirement
			ReceivedCount: 0,
			Results:       make(map[string]interface{}),
			Status:        models.BatchStatusProcessing,
			CreatedAt:     time.Now(),
		},
	})
	
	safeBatch := val.(*SafeBatch)
	
	// Lock the individual batch
	safeBatch.mu.Lock()
	defer safeBatch.mu.Unlock()

	// 2. Validate Ownership
	if safeBatch.Batch.UserID != userID {
		return errors.New("batch access denied: user_id mismatch")
	}

	// 3. Validate State
	if safeBatch.Batch.Status == models.BatchStatusComplete {
		// Depending on requirement, we might allow overwriting or error out.
		// Usually analysis is done once.
		return nil // Already done, ignore extra calls or return error
	}

	// 4. Add Result (Idempotency check for same source)
	if _, exists := safeBatch.Batch.Results[source]; !exists {
		safeBatch.Batch.Results[source] = data
		safeBatch.Batch.ReceivedCount++
	}

	// 5. Check Completion
	// Trigger strictly when we hit the count and haven't started yet
	if safeBatch.Batch.ReceivedCount >= safeBatch.Batch.ExpectedCount && !safeBatch.analysisStarted {
		safeBatch.analysisStarted = true
		// Launch Analysis in background
		go s.runAnalysis(safeBatch)
	}

	return nil
}

// runAnalysis is the aggregation logic
func (s *BatchService) runAnalysis(sb *SafeBatch) {
	// SB is a pointer to the SafeBatch in the map.
	// We need to lock to read results, but analysis itself could take time.
	// We'll read the data first.
	
	sb.mu.Lock()
	if sb.Batch.Status == models.BatchStatusComplete {
		sb.mu.Unlock()
		return
	}
	
	// Create a copy for analysis to avoid holding lock during heavy computation
	resultsCopy := make(map[string]interface{})
	for k, v := range sb.Batch.Results {
		resultsCopy[k] = v
	}
	sb.mu.Unlock()

	// --- ANALYSIS LOGIC ---
	// "Implement Analyze(results map[string]any) any"
	// Example: just summarizing keys
	
	// Simulate processing time
	time.Sleep(500 * time.Millisecond) 
	
	analysisResult := map[string]interface{}{
		"summary": fmt.Sprintf("Processed %d sources", len(resultsCopy)),
		"sources": resultsCopy,
		"timestamp": time.Now(),
		"risk_score": 0, // Mock logic
	}

	// --- SAVE RESULT ---
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.Batch.AnalysisResult = analysisResult
	sb.Batch.Status = models.BatchStatusComplete
	
	// TODO: Here we would persist to Redis/DB
}

// GetBatch retrieves the batch status and result
func (s *BatchService) GetBatch(userID, batchID string) (*models.Batch, error) {
	val, ok := s.batches.Load(batchID)
	if !ok {
		return nil, errors.New("batch not found")
	}

	sb := val.(*SafeBatch)
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.Batch.UserID != userID {
		return nil, errors.New("unauthorized batch access")
	}

	// Return a deep copy to avoid race conditions with ongoing updates
	copyBatch := *sb.Batch
	// Deep copy map if needed, but for json serialization in controller this shallow copy of struct (with map ref)
	// might be risky if map is being written to.
	// But GetBatch is read-only usually. 
	// To be safe, let's copy the Results map.
	copyBatch.Results = make(map[string]interface{})
	for k, v := range sb.Batch.Results {
		copyBatch.Results[k] = v
	}

	return &copyBatch, nil
}
