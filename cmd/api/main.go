package main

import (
	"log"
	"os"

	"quantumca-platform/internal/api"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
	"quantumca-platform/internal/ocsp"
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

	logger.Info("Starting QuantumCA API server on port", port)
	if err := server.Start(":" + port); err != nil {
		logger.Fatal("Server failed to start:", err)
	}
}