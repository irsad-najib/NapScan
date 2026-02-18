package models

import (
	"time"

	"gorm.io/gorm"
)

// CPEDefinition stores Common Platform Enumeration definitions.
// Maps to the "cpe_definitions" table.
type CPEDefinition struct {
	CPEURI    string         `json:"cpe_uri" gorm:"primaryKey;type:varchar(255)"`
	Vendor    string         `json:"vendor" gorm:"type:varchar(128);index"`
	Product   string         `json:"product" gorm:"type:varchar(128);index"`
	Version   string         `json:"version" gorm:"type:varchar(64)"`
	Part      string         `json:"part" gorm:"type:char(1)"` // 'a' = application, 'o' = os, 'h' = hardware
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// TableName overrides the table name used by Gorm to `cpe_definitions`
func (CPEDefinition) TableName() string {
	return "cpe_definitions"
}
