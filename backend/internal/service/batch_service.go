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
	batchID := uuid.New().String()
	batch := &models.Batch{
		UserID:  userID,
		BatchID: batchID,
		Status:  models.BatchStatusProcessing,
	}
	err := s.repo.Create(ctx, batch)
	if err != nil {
		return "", err
	}
	return batchID, nil
}

// ValidateBatchOwnership checks if a batch exists and belongs to the user.
func (s *BatchService) ValidateBatchOwnership(c *fiber.Ctx, batchID string) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Println("Ownership check failed: user_id not found in context")
		return fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
	}

	batch, err := s.repo.FindByID(c.Context(), batchID)
	if err != nil {
		log.Printf("Ownership check failed for batch %s: db error: %v", batchID, err)
		return fiber.NewError(fiber.StatusInternalServerError, "Could not verify batch ownership")
	}

	if batch == nil {
		log.Printf("Ownership check failed: batch %s not found for user %s", batchID, userID)
		return fiber.NewError(fiber.StatusNotFound, "Batch not found")
	}

	if batch.UserID != userID {
		log.Printf("Ownership check DENIED: user %s attempted to access batch %s owned by %s", userID, batchID, batch.UserID)
		return fiber.NewError(fiber.StatusForbidden, "You do not have permission to access this batch")
	}

	log.Printf("Ownership check ALLOWED: user %s for batch %s", userID, batchID)
	return nil
}

func (s *BatchService) GetUserBatches(ctx context.Context, userID string) ([]*models.Batch, error) {
	return s.repo.FindBatchesByUserID(ctx, userID)
}