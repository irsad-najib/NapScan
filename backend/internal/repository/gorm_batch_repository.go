package repository

import (
	"context"
	"napscan-be/internal/models"

	"gorm.io/gorm"
)

type GormBatchRepository struct {
	db *gorm.DB
}

func NewGormBatchRepository(db *gorm.DB) BatchRepository {
	db.AutoMigrate(&models.Batch{})
	return &GormBatchRepository{db: db}
}

func (r *GormBatchRepository) Create(ctx context.Context, batch *models.Batch) error {
	return r.db.WithContext(ctx).Create(batch).Error
}

func (r *GormBatchRepository) FindByID(ctx context.Context, batchID string) (*models.Batch, error) {
	var batch models.Batch

	err := r.db.WithContext(ctx).
		Preload("UploadedFiles").
		Preload("ScanResults").
		Where("batch_id = ?", batchID).
		First(&batch).Error

	if err != nil {
		return nil, err
	}

	return &batch, nil
}

func (r *GormBatchRepository) FindBatchesByUserID(ctx context.Context, userID string) ([]*models.Batch, error) {
	var batches []*models.Batch
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Preload("ScanResults").
		Preload("UploadedFiles").
		Order("created_at DESC").
		Find(&batches).Error
	return batches, err
}

func (r *GormBatchRepository) Update(ctx context.Context, batch *models.Batch) error {
	return r.db.WithContext(ctx).Save(batch).Error
}

func (r *GormBatchRepository) Delete(ctx context.Context, batchID string) error {
	return r.db.WithContext(ctx).Where("batch_id = ?", batchID).Delete(&models.Batch{}).Error
}
