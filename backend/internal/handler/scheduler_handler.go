package handler

import (
	"napscan-be/internal/models"
	"napscan-be/internal/service"
	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

type SchedulerHandler struct {
	service *service.SchedulerService
}

func NewSchedulerHandler(service *service.SchedulerService) *SchedulerHandler {
	return &SchedulerHandler{service: service}
}

// CreateSchedule adds a new scheduled scan
// @Summary Create Schedule
// @Description Create a new scheduled scan task
// @Tags Scheduler
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.Schedule true "Schedule details"
// @Success 201 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /schedule [post]
func (h *SchedulerHandler) Create(c *fiber.Ctx) error {
	var req models.Schedule
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "Invalid request body", err)
	}

	userID := c.Locals("user_id").(string)
	req.UserID = userID

	if err := h.service.Create(&req); err != nil {
		return response.InternalServerError(c, "Failed to create schedule", err)
	}

	return response.Success(c, "Schedule created successfully", req)
}

// ListSchedules returns all scheduled scans
// @Summary List Schedules
// @Description Get all scheduled scan tasks
// @Tags Scheduler
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /schedule [get]
func (h *SchedulerHandler) List(c *fiber.Ctx) error {
	schedules, err := h.service.List()
	if err != nil {
		return response.InternalServerError(c, "Failed to list schedules", err)
	}
	return response.Success(c, "Schedules retrieved successfully", schedules)
}

// DeleteSchedule removes a scheduled scan
// @Summary Delete Schedule
// @Description Delete a scheduled scan task
// @Tags Scheduler
// @Param id path string true "Schedule ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /schedule/{id} [delete]
func (h *SchedulerHandler) Delete(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.service.Delete(id); err != nil {
		return response.InternalServerError(c, "Failed to delete schedule", err)
	}
	return response.Success(c, "Schedule deleted successfully", nil)
}

// PauseSchedule pauses a scheduled scan
// @Summary Pause Schedule
// @Description Pause a scheduled scan task
// @Tags Scheduler
// @Param id path string true "Schedule ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /schedule/{id}/pause [post]
func (h *SchedulerHandler) Pause(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.service.Pause(id); err != nil {
		return response.InternalServerError(c, "Failed to pause schedule", err)
	}
	return response.Success(c, "Schedule paused successfully", nil)
}

// ResumeSchedule resumes a scheduled scan
// @Summary Resume Schedule
// @Description Resume a scheduled scan task
// @Tags Scheduler
// @Param id path string true "Schedule ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /schedule/{id}/resume [post]
func (h *SchedulerHandler) Resume(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.service.Resume(id); err != nil {
		return response.InternalServerError(c, "Failed to resume schedule", err)
	}
	return response.Success(c, "Schedule resumed successfully", nil)
}
