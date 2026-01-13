package repository

import (
	"context"
	"napscan-be/internal/models"
)

type UserRepository interface {
	Upsert(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	Delete(ctx context.Context, id string) error
}
