package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Schedule represents a scheduled scan task
type Schedule struct {
	ID             string         `json:"id" gorm:"type:char(36);primaryKey"`
	Name           string         `json:"name" gorm:"type:varchar(255);not null"`
	Target         string         `json:"target" gorm:"type:varchar(255);not null"`
	Tool           string         `json:"tool" gorm:"type:varchar(255);not null" example:"nmap,zap,openvas"` // comma-separated tools: nmap, zap, openvas, etc.
	CronExpression string         `json:"cron_expression" gorm:"type:varchar(50);not null"`
	Decision       bool           `json:"decision" gorm:"default:false"` // true = continue to dynamic analysis
	IsActive       bool           `json:"is_active" gorm:"default:true"`
	LastRun        *time.Time     `json:"last_run"`
	LastRunStatus  string         `json:"last_run_status" gorm:"type:varchar(20)"`   // success, failed, running
	LastResourceID string         `json:"last_resource_id" gorm:"type:varchar(255)"` // TaskID or BatchID
	NextRun        *time.Time     `json:"next_run"`
	UserID         string         `json:"user_id" gorm:"type:char(36);not null"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate generates a new UUID for the schedule
func (s *Schedule) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}
