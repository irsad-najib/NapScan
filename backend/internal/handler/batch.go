// buatin handler batch.go
package handler

import (
	"log"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type BatchHandler struct {
	service       *service.BatchService
	reportService *service.ReportService
}

func NewBatchHandler(s *service.BatchService, r *service.ReportService) *BatchHandler {
	return &BatchHandler{service: s, reportService: r}
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
// @Success 200 {array} models.BatchSummaryResponse
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

// GetBatchDetail retrieves detailed information about a specific batch including risk analysis
// @Summary Get Batch Detail
// @Description Get detailed information about a specific batch including normalized risk calculation and scan results
// @Tags Batch
// @Security BearerAuth
// @Produce json
// @Param batch_id path string true "Batch ID"
// @Success 200 {object} models.BatchDetailResponse
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /batch/{batch_id} [get]
func (h *BatchHandler) GetBatchDetail(c *fiber.Ctx) error {
	batchID := c.Params("batch_id")
	log.Printf("[BATCH] Received get batch detail request for batch_id=%s", batchID)

	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[BATCH] User not authenticated")
		return response.Unauthorized(c, "User not authenticated")
	}

	detail, err := h.service.GetBatchDetail(c.Context(), batchID, userID)
	if err != nil {
		log.Printf("[BATCH] Failed to get batch detail: %v", err)
		if err.Error() == "batch not found" {
			return response.NotFound(c, "Batch not found")
		}
		if err.Error() == "access denied" {
			return response.Forbidden(c, "You do not have permission to access this batch")
		}
		return response.InternalServerError(c, "Failed to get batch detail", err)
	}

	return c.JSON(detail)
}

// GetBatchReport generates and downloads a PDF report for the batch
// @Summary Download Batch Report
// @Description Generate a PDF report for a specific batch and download it
// @Tags Batch
// @Security BearerAuth
// @Produce application/pdf
// @Param batch_id path string true "Batch ID"
// @Success 200 {string} string "PDF Content"
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /batch/{batch_id}/report [get]
func (h *BatchHandler) GetBatchReport(c *fiber.Ctx) error {
	batchID := c.Params("batch_id")
	log.Printf("[BATCH] Received get report request for batch_id=%s", batchID)

	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[BATCH] User not authenticated")
		return response.Unauthorized(c, "User not authenticated")
	}

	reportData, err := h.service.GetBatchReportData(c.Context(), batchID, userID)
	if err != nil {
		log.Printf("[BATCH] Failed to get report data: %v", err)
		if err.Error() == "batch not found" {
			return response.NotFound(c, "Batch not found")
		}
		if err.Error() == "access denied" {
			return response.Forbidden(c, "You do not have permission to access this batch")
		}
		return response.InternalServerError(c, "Failed to get report data", err)
	}

	// Generate PDF
	filePath, err := h.reportService.GeneratePDF(reportData)
	if err != nil {
		log.Printf("[BATCH] Failed to generate PDF: %v", err)
		return response.InternalServerError(c, "Failed to generate report", err)
	}

	log.Printf("[BATCH_SERVICE] Report generated successfully: %s", filePath)
	return c.Download(filePath)
}

// DeleteBatch removes a batch and its associated data
// @Summary Delete Batch
// @Description Delete a specific batch
// @Tags Batch
// @Security BearerAuth
// @Produce json
// @Param batch_id path string true "Batch ID"
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /batch/{batch_id} [delete]
func (h *BatchHandler) DeleteBatch(c *fiber.Ctx) error {
	batchID := c.Params("batch_id")
	log.Printf("[BATCH] Received delete request for batch_id=%s", batchID)

	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		log.Printf("[BATCH] User not authenticated")
		return response.Unauthorized(c, "User not authenticated")
	}

	err := h.service.DeleteBatch(c.Context(), batchID, userID)
	if err != nil {
		log.Printf("[BATCH] Failed to delete batch: %v", err)
		if err.Error() == "batch not found" {
			return response.NotFound(c, "Batch not found")
		}
		if err.Error() == "access denied" {
			return response.Forbidden(c, "You do not have permission to delete this batch")
		}
		return response.InternalServerError(c, "Failed to delete batch", err)
	}

	return response.Success(c, "Batch deleted successfully", nil)
}
