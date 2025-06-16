package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"quantumca-platform/internal/api"
	"quantumca-platform/internal/ocsp"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

func main() {
	config, err := utils.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	logger := utils.NewLogger(config.LogLevel)

	db, err := storage.NewSQLiteDB(config.DatabasePath)
	if err != nil {
		logger.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	if err := storage.RunMigrations(db); err != nil {
		logger.Fatal("Failed to run migrations:", err)
	}

	ocspServer := ocsp.NewServer(db, config)
	go func() {
		if err := ocspServer.Start(); err != nil {
			logger.Error("OCSP server failed:", err)
		}
	}()

	server := api.NewServer(db, config, logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      server,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Infof("Starting QuantumCA API server on port %s", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed to start:", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown:", err)
	}

	logger.Info("Server exited")
}