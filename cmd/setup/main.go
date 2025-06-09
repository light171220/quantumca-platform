package main

import (
	"fmt"
	"log"
	"os"

	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

func main() {
	fmt.Println("Setting up QuantumCA Platform...")

	config, err := utils.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	if err := createDirectories(config); err != nil {
		log.Fatal("Failed to create directories:", err)
	}

	db, err := storage.NewSQLiteDB(config.DatabasePath)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	if err := storage.RunMigrations(db); err != nil {
		log.Fatal("Failed to run migrations:", err)
	}

	rootCA := ca.NewRootCA(config)
	if err := rootCA.Initialize(); err != nil {
		log.Fatal("Failed to initialize root CA:", err)
	}

	intermediateCA := ca.NewIntermediateCA(config, rootCA)
	if err := intermediateCA.Initialize(); err != nil {
		log.Fatal("Failed to initialize intermediate CA:", err)
	}

	fmt.Println("QuantumCA Platform setup completed successfully!")
	fmt.Println("Root CA certificate:", config.KeysPath+"/root-ca.pem")
	fmt.Println("Intermediate CA certificate:", config.KeysPath+"/intermediate-ca.pem")
	fmt.Println("You can now start the API server with: go run cmd/api/main.go")
}

func createDirectories(config *utils.Config) error {
	dirs := []string{
		config.KeysPath,
		config.CertificatesPath,
		"./data",
		"./web/static",
		"./web/templates",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	return nil
}