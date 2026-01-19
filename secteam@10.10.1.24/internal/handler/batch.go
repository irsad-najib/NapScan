// buatin handler batch.go
package handler

import (
	"log"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type BatchHandler struct {
	service *service.BatchService
}

func NewBatchHandler(s *service.BatchService) *BatchHandler {
	return &BatchHandler{service: s}
}

// CreateBatch generates a unique batch ID and associates it with the user
// @Summary Create Batch ID
// @Description Generate a unique batch ID for the authenticated user
// @Tags Batch
// @Security BearerAuth
// @Produce json
// @Success 200 {object} object{batch_id=string}
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /batch/create [post]
func (h *BatchHandler) CreateBatch(c *fiber.Ctx) error {
	log.Printf("[BATCH] Received create batch request")
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[BATCH] User not authenticated")
		return response.Unauthorized(c, "User not authenticated")
	}

	log.Printf("[BATCH] Creating batch for user_id=%s", userID)
	batchID, err := h.service.CreateBatch(c.Context(), userID)
	if err != nil {
		log.Printf("[BATCH] Failed to create batch: %v", err)
		return response.InternalServerError(c, "Failed to create batch", err)
	}

	log.Printf("[BATCH] Batch created successfully: batch_id=%s", batchID)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"batch_id": batchID,
	})
}

// GetUserBatches retrieves all batches for the authenticated user
// @Summary Get User Batches
// @Description Get a list of all batches created by the current user
// @Tags Batch
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.Batch
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /batch/list [get]
func (h *BatchHandler) GetUserBatches(c *fiber.Ctx) error {
	log.Printf("[BATCH] Received get user batches request")
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[BATCH] User not authenticated")
		return response.Unauthorized(c, "User not authenticated")
	}

	log.Printf("[BATCH] Fetching batches for user_id=%s", userID)
	batches, err := h.service.GetUserBatches(c.Context(), userID)
	if err != nil {
		log.Printf("[BATCH] Failed to retrieve batches: %v", err)
		return response.InternalServerError(c, "Failed to retrieve batches", err)
	}

	log.Printf("[BATCH] Retrieved %d batches", len(batches))
	return c.JSON(batches)
}