package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestHealthCheck(t *testing.T) {
	app := fiber.New()
	h := NewHealthHandler()
	app.Get("/health", h.Check)

	req := httptest.NewRequest("GET", "/health", nil)
	resp, err := app.Test(req)

	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	assert.Equal(t, "success", body["status"])
	assert.Equal(t, "Server is healthy", body["message"])
}
