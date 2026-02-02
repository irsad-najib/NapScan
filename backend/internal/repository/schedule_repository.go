package repository

import (
	"napscan-be/internal/models"

	"gorm.io/gorm"
)

type ScheduleRepository interface {
	Create(schedule *models.Schedule) error
	FindAll() ([]models.Schedule, error)
	FindActive() ([]models.Schedule, error)
	FindByID(id string) (*models.Schedule, error)
	Update(schedule *models.Schedule) error
	Delete(id string) error
	FindByUserID(userID string) ([]models.Schedule, error)
}

type gormScheduleRepository struct {
	db *gorm.DB
}

func NewGormScheduleRepository(db *gorm.DB) ScheduleRepository {
	return &gormScheduleRepository{db: db}
}

func (r *gormScheduleRepository) Create(schedule *models.Schedule) error {
	return r.db.Create(schedule).Error
}

func (r *gormScheduleRepository) FindAll() ([]models.Schedule, error) {
	var schedules []models.Schedule
	err := r.db.Find(&schedules).Error
	return schedules, err
}

func (r *gormScheduleRepository) FindActive() ([]models.Schedule, error) {
	var schedules []models.Schedule
	err := r.db.Where("is_active = ?", true).Find(&schedules).Error
	return schedules, err
}

func (r *gormScheduleRepository) FindByID(id string) (*models.Schedule, error) {
	var schedule models.Schedule
	err := r.db.First(&schedule, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &schedule, nil
}

func (r *gormScheduleRepository) Update(schedule *models.Schedule) error {
	return r.db.Save(schedule).Error
}

func (r *gormScheduleRepository) Delete(id string) error {
	return r.db.Delete(&models.Schedule{}, "id = ?", id).Error
}

func (r *gormScheduleRepository) FindByUserID(userID string) ([]models.Schedule, error) {
	var schedules []models.Schedule
	err := r.db.Where("user_id = ?", userID).Find(&schedules).Error
	return schedules, err
}
