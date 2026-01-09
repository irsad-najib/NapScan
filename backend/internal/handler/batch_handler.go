package handler

import (
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/service"

	"github.com/gofiber/fiber/v2"
)

type BatchHandler struct {
	batchService *service.BatchService
}

func NewBatchHandler() *BatchHandler {
	return &BatchHandler{
		batchService: service.NewBatchService(),
	}
}

// HandleScanPartA receives input for part A of the scan
// @Summary Receive Scan Part A
// @Description Receives partial scan result for Part A
// @Tags Batch
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param X-Batch-ID header string true "Batch ID"
// @Param request body models.BatchRequest false "Scan Data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/a [post]
func (h *BatchHandler) HandleScanPartA(c *fiber.Ctx) error {
	return h.handlePart(c, "api_a")
}

// HandleScanPartB receives input for part B of the scan
// @Summary Receive Scan Part B
// @Description Receives partial scan result for Part B
// @Tags Batch
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param X-Batch-ID header string true "Batch ID"
// @Success 200 {object} map[string]string
// @Router /api/b [post]
func (h *BatchHandler) HandleScanPartB(c *fiber.Ctx) error {
	return h.handlePart(c, "api_b")
}

// HandleScanPartC receives input for part C of the scan
// @Summary Receive Scan Part C
// @Description Receives partial scan result for Part C
// @Tags Batch
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param X-Batch-ID header string true "Batch ID"
// @Success 200 {object} map[string]string
// @Router /api/c [post]
func (h *BatchHandler) HandleScanPartC(c *fiber.Ctx) error {
	return h.handlePart(c, "api_c")
}

// HandleScanPartD receives input for part D of the scan
// @Summary Receive Scan Part D
// @Description Receives partial scan result for Part D
// @Tags Batch
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param X-Batch-ID header string true "Batch ID"
// @Success 200 {object} map[string]string
// @Router /api/d [post]
func (h *BatchHandler) HandleScanPartD(c *fiber.Ctx) error {
	return h.handlePart(c, "api_d")
}

// HandleScanPartE receives input for part E of the scan
// @Summary Receive Scan Part E
// @Description Receives partial scan result for Part E
// @Tags Batch
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param X-Batch-ID header string true "Batch ID"
// @Success 200 {object} map[string]string
// @Router /api/e [post]
func (h *BatchHandler) HandleScanPartE(c *fiber.Ctx) error {
	return h.handlePart(c, "api_e")
}

// handlePart is the shared logic for the fan-in endpoints
func (h *BatchHandler) handlePart(c *fiber.Ctx, sourceName string) error {
	// 1. Get UserID from context (set by AuthMiddleware)
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User ID not found in session"})
	}

	// 2. Get X-Batch-ID header
	batchID := c.Get("X-Batch-ID")
	if batchID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "X-Batch-ID header is required"})
	}

	// 3. Process Payload (mock)
	mockResult := map[string]string{
		"source":    sourceName,
		"processed": "true",
		"timestamp": time.Now().String(),
	}

	// 4. Send to Batch Manager
	err := h.batchService.AddResult(userID, batchID, sourceName, mockResult)
	if err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"status":   "received",
		"source":   sourceName,
		"batch_id": batchID,
	})
}

// GetBatchResult retrieves the aggregated analysis
// @Summary Get Batch Analysis Result
// @Description Returns the aggregated results and status of the batch
// @Tags Batch
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param batch_id path string true "Batch ID"
// @Success 200 {object} models.BatchResponse
// @Failure 404 {object} map[string]string
// @Router /api/analysis/{batch_id} [get]
func (h *BatchHandler) GetBatchResult(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User ID not found in session"})
	}

	batchID := c.Params("batch_id")
	if batchID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Batch ID required"})
	}

	batch, err := h.batchService.GetBatch(userID, batchID)
	if err != nil {
		if err.Error() == "not found" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Batch not found"})
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(models.BatchResponse{
		Status:         batch.Status,
		AnalysisResult: batch.AnalysisResult,
		BatchID:        batch.BatchID,
	})
}
