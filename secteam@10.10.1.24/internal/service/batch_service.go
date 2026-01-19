// buatkan service untuk create batch id yang unik menggunakan uuid benerin biar routesnya nanti get
package service

import (
	"context"
	"log"
	"napscan-be/internal/models"
	"napscan-be/internal/repository"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type BatchService struct {
	repo repository.BatchRepository
}

func NewBatchService(repo repository.BatchRepository) *BatchService {
	return &BatchService{repo: repo}
}

func (s *BatchService) CreateBatch(ctx context.Context, userID string) (string, error) {
	log.Printf("[BATCH_SERVICE] Creating batch for user_id=%s", userID)
	batchID := uuid.New().String()
	batch := &models.Batch{
		UserID:  userID,
		BatchID: batchID,
		Status:  models.BatchStatusProcessing,
	}
	err := s.repo.Create(ctx, batch)
	if err != nil {
		log.Printf("[BATCH_SERVICE] Failed to create batch: %v", err)
		return "", err
	}
	log.Printf("[BATCH_SERVICE] Database insert success for batch_id=%s", batchID)
	return batchID, nil
}

// ValidateBatchOwnership checks if a batch exists and belongs to the user.
func (s *BatchService) ValidateBatchOwnership(c *fiber.Ctx, batchID string) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[BATCH_SERVICE] Ownership check failed: user_id not found")
		return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
	}

	batch, err := s.repo.FindByID(c.Context(), batchID)
	if err != nil {
		log.Printf("[BATCH_SERVICE] Ownership check failed for batch_id=%s: %v", batchID, err)
		return fiber.NewError(fiber.StatusInternalServerError, "Could not verify batch ownership")
	}

	if batch == nil {
		log.Printf("[BATCH_SERVICE] Batch not found: batch_id=%s", batchID)
		return fiber.NewError(fiber.StatusNotFound, "Batch not found")
	}

	if batch.UserID != userID {
		log.Printf("[BATCH_SERVICE] Access denied: user=%s tried to access batch=%s owned by %s", userID, batchID, batch.UserID)
		return fiber.NewError(fiber.StatusForbidden, "You do not have permission to access this batch")
	}

	log.Printf("[BATCH_SERVICE] Ownership validated: user=%s batch=%s", userID, batchID)
	return nil
}

func (s *BatchService) GetUserBatches(ctx context.Context, userID string) ([]*models.Batch, error) {
	log.Printf("[BATCH_SERVICE] Fetching batches for user_id=%s", userID)
	batches, err := s.repo.FindBatchesByUserID(ctx, userID)
	if err != nil {
		log.Printf("[BATCH_SERVICE] Failed to fetch batches: %v", err)
		return nil, err
	}
	log.Printf("[BATCH_SERVICE] Found %d batches", len(batches))
	return batches, nil
}