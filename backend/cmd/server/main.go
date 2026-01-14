package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"napscan-be/internal/handler"
	"napscan-be/internal/middleware"
	"napscan-be/internal/repository"
	"napscan-be/internal/routes"
	"napscan-be/internal/service"
	"napscan-be/pkg/database"

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
// @description Type "Bearer" followed by a space and a JWT.
// @securityRequirement BearerAuth
// main boots the HTTP API server.
//
// It loads environment variables from a .env file (if present), establishes a MongoDB connection,
// wires repositories/services/handlers, registers middleware (logger, recover, CORS), exposes
// Swagger docs, and mounts API routes under /api (plus a root /health endpoint that also checks
// MongoDB connectivity). It then starts the Fiber server on PORT (default 5000) and performs a
// graceful shutdown on SIGINT/SIGTERM, closing MongoDB and stopping the HTTP server.
//
// Build behavior: saat di-build (go build), endpoint API tidak “hilang”. Semua route yang didaftarkan
// di main akan tetap ada di binary hasil build, selama code ini terpanggil dan tidak ada conditional
// compilation/build tags atau config runtime yang sengaja men-disable route tertentu.
func main() {
	// load .env if present
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize MongoDB
	ctx := context.Background()
	mongoDB, err := database.NewMongoDB(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer mongoDB.Close(ctx)

	log.Println("✅ Connected to MongoDB successfully")

	// Initialize repositories
	userRepo := repository.NewMongoDBUserRepository(mongoDB.Database)
	scanResultRepo := repository.NewMongoDBScanResultRepository(mongoDB.Database)
	batchRepo := repository.NewMongoDBBatchRepository(mongoDB.Database) // <-- ADD THIS

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
	app.Get("/api/swagger/*", fiberSwagger.New())

	// Auth routes are public and should NOT be under the protected /api group
	authService := service.NewAuthService(userRepo)
	authHandler := handler.NewAuthHandler(authService)
	// We group them under /api for path consistency, but on the main `app` instance
	// so they don't inherit the auth middleware.
	authRoutes := app.Group("/api")
	routes.AuthRoutes(authRoutes, authHandler)

	// API group with authentication middleware for all other routes
	api := app.Group("/api")

	// Terapkan middleware otentikasi
	api.Use(middleware.AuthMiddleware())

	// Services
	nmapService := service.NewNmapService()
	nucleiService := service.NewNucleiService()
	zapService := service.NewZapService()
	ffufService := service.NewFfufService()
	openvasService := service.NewOpenVASService()
	sslyzeService := service.NewSslyzeService()
	batchService := service.NewBatchService(batchRepo) // <-- UPDATE THIS

	// Handlers
	healthHandler := handler.NewHealthHandler()
	nmapHandler := handler.NewNmapHandler(nmapService, scanResultRepo, batchService) // <-- UPDATE THIS
	nucleiHandler := handler.NewNucleiHandler(nucleiService, scanResultRepo, batchService)
	zapHandler := handler.NewZapHandler(zapService, scanResultRepo, batchService)
	ffufHandler := handler.NewFfufHandler(ffufService, scanResultRepo, batchService)
	openvasHandler := handler.NewOpenVASHandler(openvasService, scanResultRepo, batchService)
	sslyzeHandler := handler.NewSslyzeHandler(sslyzeService, scanResultRepo, batchService)
	mobsfHandler := handler.NewMobSFHandler(scanResultRepo, batchService)

	// Auth & Batch Handlers
	batchHandler := handler.NewBatchHandler(batchService) // <-- UPDATE THIS

	// Health Check Route (public, so defined on `app`, not `api`)
	app.Get("/health", func(c *fiber.Ctx) error {
		// Check MongoDB connection
		if err := mongoDB.Ping(c.Context()); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status":   "unhealthy",
				"database": "disconnected",
				"error":    err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"status":   "healthy",
			"database": "connected",
		})
	})
	api.Get("/health", healthHandler.Check)

	// Routes (now protected by middleware)
	routes.MobSFRoutes(api, mobsfHandler)
	routes.NmapRoutes(api, nmapHandler)
	routes.NucleiRoutes(api, nucleiHandler)
	routes.ZapRoutes(api, zapHandler)
	routes.FfufRoutes(api, ffufHandler)
	routes.OpenVASRoutes(api, openvasHandler)
	routes.SslyzeRoutes(api, sslyzeHandler)
	routes.BatchRoutes(api, batchHandler) // <-- Batch routes are now protected

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down server...")
		
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		if err := mongoDB.Close(shutdownCtx); err != nil {
			log.Printf("Error closing MongoDB: %v", err)
		}
		
		if err := app.Shutdown(); err != nil {
			log.Printf("Error shutting down server: %v", err)
		}
	}()

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	log.Printf("🚀 Server starting on port %s", port)
	log.Fatal(app.Listen(":" + port))
}
