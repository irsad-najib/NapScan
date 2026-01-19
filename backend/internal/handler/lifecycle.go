package handler

import (
	"encoding/json"
	"fmt"

	"napscan-be/internal/models"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type LifecycleHandler struct {
	lifecycle    *service.LifecycleService
	batchService *service.BatchService
}

type DecisionRequest struct {
	Decision string `json:"decision" example:"CONTINUE"` // STOP or CONTINUE
}


func NewLifecycleHandler(lifecycle *service.LifecycleService, batchService *service.BatchService) *LifecycleHandler {
	return &LifecycleHandler{
		lifecycle:    lifecycle,
		batchService: batchService,
	}
}

// GetFileStatus returns the current status and summary of a file
// @Summary Get File Status
// @Description Get lifecycle status and scanning summary
// @Tags Lifecycle
// @Security BearerAuth
// @Produce json
// @Param id path int true "File ID"
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /files/{id}/status [get]
func (h *LifecycleHandler) GetFileStatus(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return response.BadRequest(c, "Invalid file ID", err)
	}

	file, err := h.lifecycle.GetFile(uint(id))
	if err != nil {
		return response.Error(c, fiber.StatusNotFound, "File not found", err.Error())
	}

	// Validate batch ownership
	if err := h.batchService.ValidateBatchOwnership(c, file.BatchID); err != nil {
		return err
	}

	// Prepare response with unmarshaled findings
	
	respMap := fiber.Map{
		"id":           file.ID,
		"batch_id":     file.BatchID,
		"file_name":    file.FileName,
		"hash":         file.Hash,
		"status":       file.Status,
		"severity":     file.Severity,
		"error":        file.Error,
		"created_at":   file.CreatedAt,
		"updated_at":   file.UpdatedAt,
		"findings":     nil, // Use "findings" key for FE object
	}
	
	if file.Findings != "" {
		var fm map[string]interface{}
		if err := json.Unmarshal([]byte(file.Findings), &fm); err == nil {
			respMap["findings"] = fm
		} else {
			// If not valid JSON, send as string or empty?
			// User said "Ensure Frida Output is FE-friendly (JSON)".
			// We try our best.
		}
	}

	return response.Success(c, "File status retrieved", respMap)
}

// SubmitUserDecision handles the user's choice to stop or continue to Frida
// @Summary Submit User Decision
// @Description Choose to STOP or CONTINUE to dynamic analysis
// @Tags Lifecycle
// @Security BearerAuth
// @Produce json
// @Param id path int true "File ID"
// @Param decision body DecisionRequest true "User decision"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /files/{id}/decision [post]
func (h *LifecycleHandler) SubmitUserDecision(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return response.BadRequest(c, "Invalid file ID", err)
	}

	// 1. Get file to check batch ID
	file, err := h.lifecycle.GetFile(uint(id))
	if err != nil {
		return response.Error(c, fiber.StatusNotFound, "File not found", err.Error())
	}

	// 2. Validate ownership
	if err := h.batchService.ValidateBatchOwnership(c, file.BatchID); err != nil {
		return err
	}

	var req DecisionRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request body", err)
	}

	if req.Decision != "STOP" && req.Decision != "CONTINUE" {
		return response.BadRequest(c, "Invalid decision. Must be STOP or CONTINUE", nil)
	}

	var newStatus models.FileStatus
	if req.Decision == "STOP" {
		newStatus = models.FileStatusCompleted
		if err := h.lifecycle.UpdateStatus(uint(id), newStatus, ""); err != nil {
			return response.InternalServerError(c, "Failed to update status", err)
		}
	} else {
		newStatus = models.FileStatusFridaRunning
		// Use StartFrida which handles validation and async execution
		if err := h.lifecycle.StartFrida(uint(id)); err != nil {
			return response.InternalServerError(c, "Failed to start Frida scan", err)
		}
	}

	return response.Success(c, fmt.Sprintf("Decision %s processed", req.Decision), fiber.Map{
		"new_status": newStatus,
	})
}
