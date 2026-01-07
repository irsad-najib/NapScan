package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"napscan-be/src/routes"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// load .env if present
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Use Gin's default logger and recovery middleware
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	api := router.Group("/api")

	// Basic health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Configure server
	port := os.Getenv("PORT")

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Register routes
	nmapRoutes := routes.NmapRoutes{}
	nmapRoutes.SetupRoutes(api)

	ffufRoutes := routes.FfufRoutes{}
	ffufRoutes.SetupRoutes(api)

	zapRoutes := routes.ZapRoutes{}
	zapRoutes.SetupRoutes(api)

	nucleiRoutes := routes.NucleiRoutes{}
	nucleiRoutes.SetupRoutes(api)

	sslyzeRoutes := routes.SslyzeRoutes{}
	sslyzeRoutes.SetupRoutes(api)

	// Start server in background
	go func() {
		log.Printf("starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("received signal %s, shutting down...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	log.Println("server exiting")
}