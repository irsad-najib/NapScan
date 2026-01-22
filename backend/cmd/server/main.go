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
	"napscan-be/internal/models"
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
// It loads environment variables from a .env file (if present), establishes a MySQL connection,
// wires repositories/services/handlers, registers middleware (logger, recover, CORS), exposes
// Swagger docs, and mounts API routes under /api (plus a root /health endpoint that also checks
// database connectivity). It then starts the Fiber server on PORT (default 5000) and performs a
// graceful shutdown on SIGINT/SIGTERM, closing the database and stopping the HTTP server.
//
// Build behavior: saat di-build (go build), endpoint API tidak “hilang”. Semua route yang didaftarkan
// di main akan tetap ada di binary hasil build, selama code ini terpanggil dan tidak ada conditional
// compilation/build tags atau config runtime yang sengaja men-disable route tertentu.
func main() {
	// load .env if present
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize MySQL
	db, err := database.NewMySQL()
	if err != nil {
		log.Fatalf("Failed to connect to MySQL: %v", err)
	}
	log.Println("✅ Connected to MySQL successfully")

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get sql.DB from GORM: %v", err)
	}

	// Auto-migrate models
	err = db.AutoMigrate(&models.User{}, &models.ScanResult{}, &models.Batch{}, &models.UploadedFile{})
	if err != nil {
		log.Fatalf("Failed to auto-migrate models: %v", err)
	}

	// Initialize repositories
	userRepo := repository.NewGormUserRepository(db)
	scanResultRepo := repository.NewGormScanResultRepository(db)
	batchRepo := repository.NewGormBatchRepository(db)

	app := fiber.New(fiber.Config{
		// Set BodyLimit to 100MB for large file uploads (APKs, etc.)
		BodyLimit: 100 * 1024 * 1024,
		
		// Disable startup message untuk development yang lebih bersih
		DisableStartupMessage: false,
		
		// Reduce server header untuk keamanan
		ServerHeader: "",
		
		// Enable prefork untuk performance (optional, bisa di-disable untuk debugging)
		// Prefork: true,
		
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
	batchService := service.NewBatchService(batchRepo)
	lifecycleService := service.NewLifecycleService(db)
	
	// Initialize global ScanManager for async scan orchestration
	scanManager := service.NewScanManager()
	
	// Start cleanup worker (TTL 24h, check every 1h)
	lifecycleService.StartCleanupWorker(context.Background(), 24*time.Hour, 1*time.Hour)

	// Handlers
	healthHandler := handler.NewHealthHandler()
	scanHandler := handler.NewScanHandler(scanManager) // Unified scan control handler
	nmapHandler := handler.NewNmapHandler(nmapService, scanResultRepo, batchService, scanManager)
	nucleiHandler := handler.NewNucleiHandler(nucleiService, scanResultRepo, batchService)
	zapHandler := handler.NewZapHandler(zapService, scanResultRepo, batchService, scanManager)
	ffufHandler := handler.NewFfufHandler(ffufService, scanResultRepo, batchService, scanManager)
	openvasHandler := handler.NewOpenVASHandler(openvasService, scanResultRepo, batchService)
	sslyzeHandler := handler.NewSslyzeHandler(sslyzeService, scanResultRepo, batchService, scanManager)
	lifecycleHandler := handler.NewLifecycleHandler(lifecycleService, batchService)
	mobsfHandler := handler.NewMobSFHandler(scanResultRepo, batchService, lifecycleService)

	// Auth & Batch Handlers
	batchHandler := handler.NewBatchHandler(batchService)

	// Health Check Route (public, so defined on `app`, not `api`)
	app.Get("/health", func(c *fiber.Ctx) error {
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sqlDB.PingContext(pingCtx); err != nil {
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
	routes.NmapRoutes(api, nmapHandler, scanHandler)
	routes.NucleiRoutes(api, nucleiHandler)
	routes.ZapRoutes(api, zapHandler, scanHandler)
	routes.FfufRoutes(api, ffufHandler, scanHandler)
	routes.OpenVASRoutes(api, openvasHandler)
	routes.SslyzeRoutes(api, sslyzeHandler, scanHandler)
	routes.BatchRoutes(api, batchHandler) // <-- Batch routes are now protected
	routes.LifecycleRoutes(api, lifecycleHandler)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down server...")
		_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := sqlDB.Close(); err != nil {
			log.Printf("Error closing MySQL connection: %v", err)
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
