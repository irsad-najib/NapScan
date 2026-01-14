package repository

import (
	"context"

	"napscan-be/internal/models"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ScanResultRepository interface {
	Insert(ctx context.Context, scan *models.ScanResult) (primitive.ObjectID, error)
}
