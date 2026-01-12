package main

import (
	"log"
	"os"

	"napscan-be/internal/handler"
	"napscan-be/internal/middleware"
	"napscan-be/internal/routes"
	"napscan-be/internal/service"

	_ "napscan-be/docs" // Uncomment after running swag init

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	fiberSwagger "github.com/gofiber/swagger"
	"github.com/joho/godotenv"
)

// @title Napscan API
// @version 1.0
// @description Security Scanning API
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @email support@swagger.io
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @BasePath /api
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	// load .env if present
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	app := fiber.New(fiber.Config{
		// Set BodyLimit to 100MB for large file uploads (APKs, etc.)
		BodyLimit: 100 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
			})
		},
	})

	// Middleware
	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(middleware.CORSMiddleware())

	// Swagger
	app.Get("/swagger/*", fiberSwagger.New())

	api := app.Group("/api")

	// Services
	nmapService := service.NewNmapService()
	nucleiService := service.NewNucleiService()
	zapService := service.NewZapService()
	ffufService := service.NewFfufService()
	openvasService := service.NewOpenVASService()
	sslyzeService := service.NewSslyzeService()

	// Handlers
	healthHandler := handler.NewHealthHandler()
	nmapHandler := handler.NewNmapHandler(nmapService)
	nucleiHandler := handler.NewNucleiHandler(nucleiService)
	zapHandler := handler.NewZapHandler(zapService)
	ffufHandler := handler.NewFfufHandler(ffufService)
	openvasHandler := handler.NewOpenVASHandler(openvasService)
	sslyzeHandler := handler.NewSslyzeHandler(sslyzeService)
	
	// Auth & Batch Handlers
	authHandler := handler.NewAuthHandler()

	// Health Check Route
	app.Get("/health", healthHandler.Check)
	api.Get("/health", healthHandler.Check)

	// Routes
	routes.MobSFRoutes(api)
	routes.NmapRoutes(api, nmapHandler)
	routes.NucleiRoutes(api, nucleiHandler)
	routes.ZapRoutes(api, zapHandler)
	routes.FfufRoutes(api, ffufHandler)
	routes.OpenVASRoutes(api, openvasHandler)
	routes.SslyzeRoutes(api, sslyzeHandler)

	// Auth & Batch Routes
	routes.AuthRoutes(app, authHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(app.Listen(":" + port))
}
