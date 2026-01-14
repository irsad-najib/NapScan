package repository

import (
	"context"
	"napscan-be/internal/models"

	"gorm.io/gorm"
)

type GormScanResultRepository struct {
	db *gorm.DB
}

func NewGormScanResultRepository(db *gorm.DB) ScanResultRepository {
	db.AutoMigrate(&models.ScanResult{})
	return &GormScanResultRepository{db: db}
}

func (r *GormScanResultRepository) Insert(ctx context.Context, scan *models.ScanResult) (interface{}, error) {
	err := r.db.WithContext(ctx).Create(scan).Error
	return scan.ID, err
}

func (r *GormScanResultRepository) FindByBatchID(ctx context.Context, batchID string) ([]models.ScanResult, error) {
	var results []models.ScanResult
	err := r.db.WithContext(ctx).Where("batch_id = ?", batchID).Find(&results).Error
	return results, err
}
