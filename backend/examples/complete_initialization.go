package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"napscan-be/internal/handler"
	"napscan-be/internal/middleware"
	"napscan-be/internal/scanner"
	"napscan-be/internal/scanners"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Initialize database
	db, err := initDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize scanner registry
	registry := initScannerRegistry()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} (${latency})\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: getEnv("CORS_ORIGINS", "*"),
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))

	// Initialize handlers
	authHandler := handler.NewAuthHandler()
	scanHandler := handler.NewScanHandler(db, registry)

	// Health check endpoint (no auth required)
	app.Get("/health", func(c *fiber.Ctx) error {
		// Validate scanner availability
		errors := registry.ValidateAll()
		
		status := "healthy"
		availableTools := []string{}
		unavailableTools := []string{}
		
		for _, toolName := range registry.List() {
			if _, hasError := errors[toolName]; hasError {
				unavailableTools = append(unavailableTools, toolName)
				status = "degraded"
			} else {
				availableTools = append(availableTools, toolName)
			}
		}
		
		return c.JSON(fiber.Map{
			"status":             status,
			"timestamp":          time.Now(),
			"database":           "connected",
			"available_tools":    availableTools,
			"unavailable_tools":  unavailableTools,
		})
	})

	// Public routes
	app.Post("/api/auth/login", authHandler.Login)
	app.Post("/api/auth/register", authHandler.Register)

	// Protected routes
	api := app.Group("/api", middleware.AuthMiddleware())
	
	// Scan endpoints
	api.Post("/scans", scanHandler.CreateScan)
	api.Get("/scans", scanHandler.ListBatches)
	api.Get("/scans/:batchId", scanHandler.GetBatchStatus)
	api.Get("/scans/:batchId/report", scanHandler.GetBatchReport)
	
	// Scanner info endpoint
	api.Get("/scanners", func(c *fiber.Ctx) error {
		scanners := registry.List()
		validationErrors := registry.ValidateAll()
		
		scannerInfo := make([]map[string]interface{}, 0, len(scanners))
		for _, name := range scanners {
			info := map[string]interface{}{
				"name":      name,
				"available": true,
			}
			
			if err, hasError := validationErrors[name]; hasError {
				info["available"] = false
				info["error"] = err.Error()
			}
			
			scannerInfo = append(scannerInfo, info)
		}
		
		return c.JSON(fiber.Map{
			"scanners": scannerInfo,
			"total":    len(scanners),
		})
	})

	// Start server
	port := getEnv("PORT", "8080")
	log.Printf("🚀 NapScan server starting on port %s", port)
	log.Printf("📊 Registered scanners: %v", registry.List())
	
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// initDatabase initializes the database connection
func initDatabase() (*sql.DB, error) {
	dbURL := getEnv("DATABASE_URL", "")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	maxOpenConns := getEnvInt("DB_MAX_OPEN_CONNS", 25)
	maxIdleConns := getEnvInt("DB_MAX_IDLE_CONNS", 5)
	connMaxLifetime := getEnvInt("DB_CONN_MAX_LIFETIME", 300) // seconds

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Second)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("✅ Database connected successfully")
	return db, nil
}

// initScannerRegistry initializes and registers all scanners
func initScannerRegistry() scanner.ScannerRegistry {
	registry := scanner.NewRegistry()

	// Register all available scanners
	scannerList := []scanner.Scanner{
		scanners.NewNmapScanner(),
		scanners.NewNucleiScanner(),
		// Add more scanners as they are implemented:
		// scanners.NewSSLyzeScanner(),
		// scanners.NewFfufScanner(),
		// scanners.NewZAPScanner(),
		// scanners.NewOpenVASScanner(),
	}

	for _, s := range scannerList {
		if err := registry.Register(s); err != nil {
			log.Printf("⚠️  Failed to register scanner %s: %v", s.Name(), err)
		} else {
			log.Printf("✅ Registered scanner: %s", s.Name())
		}
	}

	// Validate all scanners
	errors := registry.ValidateAll()
	for name, err := range errors {
		log.Printf("⚠️  Scanner %s validation failed: %v", name, err)
	}

	return registry
}

// customErrorHandler handles errors globally
func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error":   err.Error(),
		"code":    code,
		"path":    c.Path(),
		"method":  c.Method(),
	})
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt retrieves an integer environment variable or returns a default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
