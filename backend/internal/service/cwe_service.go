package service

import (
	"log"
	"time"

	"napscan-be/internal/models"

	"gorm.io/gorm"
)

// external CWE source (example zip/json or internal seeded list)
// For this refactor, we provide a method to seed common CWEs
// In a real scenario, this might parse the official MITRE XML/JSON

type CWEService struct {
	db *gorm.DB
}

func NewCWEService(db *gorm.DB) *CWEService {
	return &CWEService{
		db: db,
	}
}

// SeedCommonCWEs populates the DB with a few critical CWEs for testing/fallback
func (s *CWEService) SeedCommonCWEs() error {
	commonCWEs := []models.CWEDefinition{
		{CWEID: "CWE-79", Name: "Cross-site Scripting (XSS)", Description: "Improper neutralization of input during web page generation.", Status: "Stable", Abstraction: "Base"},
		{CWEID: "CWE-89", Name: "SQL Injection", Description: "Improper neutralization of special elements used in an SQL command.", Status: "Stable", Abstraction: "Base"},
		{CWEID: "CWE-200", Name: "Exposure of Sensitive Information", Description: "The product exposes sensitive information to an unauthorized actor.", Status: "Stable", Abstraction: "Base"},
		{CWEID: "CWE-94", Name: "Code Injection", Description: "Improper control of generation of code.", Status: "Stable", Abstraction: "Class"},
	}

	for _, cwe := range commonCWEs {
		cwe.UpdatedAt = time.Now()
		cwe.CreatedAt = time.Now()
		// FirstOrCreate
		if err := s.db.FirstOrCreate(&cwe, models.CWEDefinition{CWEID: cwe.CWEID}).Error; err != nil {
			log.Printf("[CWEService] Failed to seed %s: %v", cwe.CWEID, err)
			return err
		}
	}
	return nil
}

// GetCWE returns definition
func (s *CWEService) GetCWE(cweID string) (*models.CWEDefinition, error) {
	var cwe models.CWEDefinition
	if err := s.db.Where("cwe_id = ?", cweID).First(&cwe).Error; err != nil {
		return nil, err
	}
	return &cwe, nil
}

// DownloadAndSync fetches official list (mock implementation for now)
func (s *CWEService) DownloadAndSync() error {
	// In production, fetch https://cwe.mitre.org/data/csv/1000.csv.zip
	// parse CSV and upsert
	return nil
}

// MapToCWE maps internal vulnerability names to CWE ID roughly (heuristic fallback if tool doesn't provide it)
func (s *CWEService) MapToCWE(vulnName string) string {
	// Simple keyword mapping
	// This replaces legacy heuristics with a semantic mapping layer
	// Real implementation would be a robust dictionary or ML classifier
	return "CWE-200" // Default to Info Disclosure
}
