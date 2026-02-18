package models

import (
	"time"

	"gorm.io/gorm"
)

// CWEDefinition stores Common Weakness Enumeration definitions.
// Maps to the "cwe_definitions" table.
type CWEDefinition struct {
	CWEID       string         `json:"cwe_id" gorm:"primaryKey;type:varchar(64)"`
	Name        string         `json:"name" gorm:"type:varchar(255)"`
	Description string         `json:"description" gorm:"type:text"`
	Abstraction string         `json:"abstraction" gorm:"type:varchar(64)"` // e.g., Class, Base, Variant
	Status      string         `json:"status" gorm:"type:varchar(32)"`      // e.g., Draft, Stable, Deprecated
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

// TableName overrides the table name used by Gorm to `cwe_definitions`
func (CWEDefinition) TableName() string {
	return "cwe_definitions"
}
