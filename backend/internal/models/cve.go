package models

import (
	"time"

	"gorm.io/gorm"
)

// CVECache stores cached CVE data fetched from NVD.
// Maps to the "cve_cache" table.
type CVECache struct {
	CVEID       string         `json:"cve_id" gorm:"primaryKey;type:varchar(64)"`
	CWEID       *string        `json:"cwe_id" gorm:"type:varchar(64);index"` // Nullable FK to CWEDefinition if applicable
	CVSSScore   float64        `json:"cvss_score" gorm:"type:decimal(4,1)"`
	CVSSVector  string         `json:"cvss_vector" gorm:"type:varchar(255)"`
	Severity    string         `json:"severity" gorm:"type:varchar(32)"`
	Description string         `json:"description" gorm:"type:text"`
	PublishedAt time.Time      `json:"published_at"`
	LastSynced  time.Time      `json:"last_synced"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

// TableName overrides the table name used by Gorm to `cve_cache`
func (CVECache) TableName() string {
	return "cve_cache"
}
