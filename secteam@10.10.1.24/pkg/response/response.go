package response

import "github.com/gofiber/fiber/v2"

// Standard JSON response structure
type Response struct {
Success bool        `json:"success"`
Message string      `json:"message,omitempty"`
Data    interface{} `json:"data,omitempty"`
Error   interface{} `json:"error,omitempty"`
}

func Success(c *fiber.Ctx, message string, data interface{}) error {
return c.Status(fiber.StatusOK).JSON(Response{
Success: true,
Message: message,
Data:    data,
})
}

func Error(c *fiber.Ctx, status int, message string, err interface{}) error {
return c.Status(status).JSON(Response{
Success: false,
Message: message,
Error:   err,
})
}

// BadRequest is a shortcut for 400 errors
func BadRequest(c *fiber.Ctx, message string, err error) error {
errMsg := ""
if err != nil {
errMsg = err.Error()
}
return Error(c, fiber.StatusBadRequest, message, errMsg)
}

// InternalServerError is a shortcut for 500 errors
func InternalServerError(c *fiber.Ctx, message string, err error) error {
errMsg := ""
if err != nil {
errMsg = err.Error()
}
return Error(c, fiber.StatusInternalServerError, message, errMsg)
}

// Unauthorized shortcut
func Unauthorized(c *fiber.Ctx, message string) error {
return Error(c, fiber.StatusUnauthorized, message, nil)
}
