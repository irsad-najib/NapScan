package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"napscan-be/internal/scanner"

	"github.com/google/uuid"
)

// BatchRepository handles database operations for batches
type BatchRepository struct {
	db *sql.DB
}

// NewBatchRepository creates a new batch repository
func NewBatchRepository(db *sql.DB) *BatchRepository {
	return &BatchRepository{db: db}
}

// Batch represents a scan batch in the database
type Batch struct {
	ID                 uuid.UUID
	BatchID            string
	UserID             string
	Target             string
	ExpectedJobCount   int
	CompletedJobCount  int
	FailedJobCount     int
	Status             string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	CompletedAt        *time.Time
}

// ScanJob represents a scan job in the database
type ScanJob struct {
	ID           uuid.UUID
	BatchID      uuid.UUID
	ToolName     string
	Status       scanner.ScanStatus
	Target       string
	Config       json.RawMessage
	StartTime    *time.Time
	EndTime      *time.Time
	DurationMs   *int64
	RawResult    json.RawMessage
	ErrorMessage string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CreateBatch creates a new batch in the database
func (r *BatchRepository) CreateBatch(ctx context.Context, batch *Batch) error {
	query := `
		INSERT INTO batches (batch_id, user_id, target, expected_job_count, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`
	
	now := time.Now()
	return r.db.QueryRowContext(
		ctx, query,
		batch.BatchID,
		batch.UserID,
		batch.Target,
		batch.ExpectedJobCount,
		batch.Status,
		now,
		now,
	).Scan(&batch.ID, &batch.CreatedAt, &batch.UpdatedAt)
}

// GetBatchByID retrieves a batch by ID
func (r *BatchRepository) GetBatchByID(ctx context.Context, batchID string, userID string) (*Batch, error) {
	query := `
		SELECT id, batch_id, user_id, target, expected_job_count, completed_job_count, 
		       failed_job_count, status, created_at, updated_at, completed_at
		FROM batches
		WHERE batch_id = $1 AND user_id = $2
	`
	
	batch := &Batch{}
	err := r.db.QueryRowContext(ctx, query, batchID, userID).Scan(
		&batch.ID,
		&batch.BatchID,
		&batch.UserID,
		&batch.Target,
		&batch.ExpectedJobCount,
		&batch.CompletedJobCount,
		&batch.FailedJobCount,
		&batch.Status,
		&batch.CreatedAt,
		&batch.UpdatedAt,
		&batch.CompletedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	
	return batch, err
}

// UpdateBatchStatus updates the status of a batch
func (r *BatchRepository) UpdateBatchStatus(ctx context.Context, batchID uuid.UUID, status string) error {
	query := `
		UPDATE batches 
		SET status = $1, 
		    completed_at = CASE WHEN $1 IN ('completed', 'failed', 'canceled') THEN NOW() ELSE completed_at END,
		    updated_at = NOW()
		WHERE id = $2
	`
	
	_, err := r.db.ExecContext(ctx, query, status, batchID)
	return err
}

// CreateScanJob creates a new scan job
func (r *BatchRepository) CreateScanJob(ctx context.Context, job *ScanJob) error {
	query := `
		INSERT INTO scan_jobs (batch_id, tool_name, status, target, config, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`
	
	now := time.Now()
	return r.db.QueryRowContext(
		ctx, query,
		job.BatchID,
		job.ToolName,
		job.Status,
		job.Target,
		job.Config,
		now,
		now,
	).Scan(&job.ID, &job.CreatedAt, &job.UpdatedAt)
}

// UpdateScanJob updates a scan job with results
func (r *BatchRepository) UpdateScanJob(ctx context.Context, job *ScanJob) error {
	query := `
		UPDATE scan_jobs 
		SET status = $1, 
		    start_time = $2,
		    end_time = $3,
		    duration_ms = $4,
		    raw_result = $5,
		    error_message = $6,
		    updated_at = NOW()
		WHERE id = $7
	`
	
	_, err := r.db.ExecContext(
		ctx, query,
		job.Status,
		job.StartTime,
		job.EndTime,
		job.DurationMs,
		job.RawResult,
		job.ErrorMessage,
		job.ID,
	)
	
	return err
}

// GetScanJobsByBatchID retrieves all scan jobs for a batch
func (r *BatchRepository) GetScanJobsByBatchID(ctx context.Context, batchID uuid.UUID) ([]ScanJob, error) {
	query := `
		SELECT id, batch_id, tool_name, status, target, config, start_time, end_time,
		       duration_ms, raw_result, error_message, created_at, updated_at
		FROM scan_jobs
		WHERE batch_id = $1
		ORDER BY created_at
	`
	
	rows, err := r.db.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var jobs []ScanJob
	for rows.Next() {
		var job ScanJob
		err := rows.Scan(
			&job.ID,
			&job.BatchID,
			&job.ToolName,
			&job.Status,
			&job.Target,
			&job.Config,
			&job.StartTime,
			&job.EndTime,
			&job.DurationMs,
			&job.RawResult,
			&job.ErrorMessage,
			&job.CreatedAt,
			&job.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	
	return jobs, rows.Err()
}

// ListBatchesByUser retrieves batches for a user with pagination
func (r *BatchRepository) ListBatchesByUser(ctx context.Context, userID string, limit, offset int) ([]Batch, error) {
	query := `
		SELECT id, batch_id, user_id, target, expected_job_count, completed_job_count,
		       failed_job_count, status, created_at, updated_at, completed_at
		FROM batches
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	
	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var batches []Batch
	for rows.Next() {
		var batch Batch
		err := rows.Scan(
			&batch.ID,
			&batch.BatchID,
			&batch.UserID,
			&batch.Target,
			&batch.ExpectedJobCount,
			&batch.CompletedJobCount,
			&batch.FailedJobCount,
			&batch.Status,
			&batch.CreatedAt,
			&batch.UpdatedAt,
			&batch.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		batches = append(batches, batch)
	}
	
	return batches, rows.Err()
}
