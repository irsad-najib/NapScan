package repository

import (
	"context"

	"napscan-be/internal/models"
)

type ScanResultRepository interface {
	Insert(ctx context.Context, scan *models.ScanResult) (interface{}, error)
	FindByBatchID(ctx context.Context, batchID string) ([]models.ScanResult, error)
}
