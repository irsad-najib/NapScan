package repository

import (
	"context"
	"napscan-be/internal/models"

	"gorm.io/gorm"
)

type FindingRepository interface {
	Create(ctx context.Context, finding *models.DetectedFinding) error
	GetByBatchID(ctx context.Context, batchID string) ([]models.DetectedFinding, error)
	GetByBatchIDAndTool(ctx context.Context, batchID, tool string) ([]models.DetectedFinding, error)
}

type GormFindingRepository struct {
	db *gorm.DB
}

func NewGormFindingRepository(db *gorm.DB) FindingRepository {
	return &GormFindingRepository{db: db}
}

func (r *GormFindingRepository) Create(ctx context.Context, finding *models.DetectedFinding) error {
	return r.db.WithContext(ctx).Create(finding).Error
}

func (r *GormFindingRepository) GetByBatchID(ctx context.Context, batchID string) ([]models.DetectedFinding, error) {
	var findings []models.DetectedFinding
	// We assume ScanID in DetectedFinding stores the BatchID as per SchedulerService logic
	err := r.db.WithContext(ctx).Where("scan_id = ?", batchID).Find(&findings).Error
	return findings, err
}

func (r *GormFindingRepository) GetByBatchIDAndTool(ctx context.Context, batchID, tool string) ([]models.DetectedFinding, error) {
	var findings []models.DetectedFinding
	err := r.db.WithContext(ctx).
		Where("scan_id = ? AND scanner = ?", batchID, tool).
		Find(&findings).Error
	return findings, err
}
