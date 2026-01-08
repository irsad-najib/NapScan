package handler

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"napscan-be/pkg/response"

	"github.com/gofiber/fiber/v2"
)

// UploadMobSFFile uploads a file for MobSF analysis
// @Summary Upload file for MobSF
// @Description Upload APK/IPA/ZIP file for analysis
// @Tags MobSF
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "File to upload"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /mobsf/upload [post]
func UploadMobSFFile(c *fiber.Ctx) error {
	// Get the file from the request
	fileHeader, err := c.FormFile("file")
	if err != nil {
		return response.BadRequest(c, "Failed to get file from request", err)
	}

	// Open the uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		return response.InternalServerError(c, "Failed to open uploaded file", err)
	}
	defer file.Close()

	// Ensure uploads directory exists
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		os.Mkdir("uploads", 0755)
	}

	// Create a destination file
	dstPath := filepath.Join("uploads", fileHeader.Filename)
	dst, err := os.Create(dstPath)
	if err != nil {
		return response.InternalServerError(c, "Failed to create destination file", err)
	}
	defer dst.Close()

	// Copy the uploaded file to the destination file
	if _, err := io.Copy(dst, file); err != nil {
		return response.InternalServerError(c, "Failed to save uploaded file", err)
	}

	// Return success response
	return response.Success(c, fmt.Sprintf("File %s uploaded successfully", fileHeader.Filename), fiber.Map{
		"filename": fileHeader.Filename,
		"path":     dstPath,
	})
}
