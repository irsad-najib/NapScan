package repository

import (
	"context"
	"napscan-be/internal/models"

	"gorm.io/gorm"
)

type GormUserRepository struct {
	db *gorm.DB
}

func NewGormUserRepository(db *gorm.DB) UserRepository {
	db.AutoMigrate(&models.User{})
	return &GormUserRepository{db: db}
}

func (r *GormUserRepository) Upsert(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *GormUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *GormUserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *GormUserRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.User{}).Error
}
