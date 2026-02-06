package repository

import (
	"context"
	"napscan-be/internal/models"
)

type BatchRepository interface {
	Create(ctx context.Context, batch *models.Batch) error
	FindByID(ctx context.Context, batchID string) (*models.Batch, error)
	FindBatchesByUserID(ctx context.Context, userID string) ([]*models.Batch, error)
	Delete(ctx context.Context, batchID string) error
}
