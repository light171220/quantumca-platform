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

	if err := validateConfig(config); err != nil {
		log.Fatal("Configuration validation failed:", err)
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

	fmt.Println("Initializing Root CA with encrypted key storage...")
	rootCA := ca.NewRootCA(config)
	if err := rootCA.Initialize(); err != nil {
		log.Fatal("Failed to initialize root CA:", err)
	}

	fmt.Println("Initializing Intermediate CA with encrypted key storage...")
	intermediateCA := ca.NewIntermediateCA(config, rootCA)
	if err := intermediateCA.Initialize(); err != nil {
		log.Fatal("Failed to initialize intermediate CA:", err)
	}

	if err := validateCAs(rootCA, intermediateCA); err != nil {
		log.Fatal("CA validation failed:", err)
	}

	fmt.Println("\n✅ QuantumCA Platform setup completed successfully!")
	fmt.Println("📁 Key storage directory:", config.KeysPath)
	fmt.Println("🔐 Keys are encrypted at rest using AES-256-GCM")
	fmt.Println("🌐 Domain validation is enabled")
	fmt.Println("🔗 Certificate chain validation is enabled")
	fmt.Println("\n🚀 You can now start the API server with: go run cmd/api/main.go")

	printSecurityInfo(config)
}

func validateConfig(config *utils.Config) error {
	if err := config.ValidateSecuritySettings(); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	securityConfig := config.GetSecurityConfig()
	if !securityConfig["key_encryption_enabled"].(bool) {
		return fmt.Errorf("key encryption must be enabled")
	}

	if !securityConfig["domain_validation_required"].(bool) {
		return fmt.Errorf("domain validation must be enabled")
	}

	if !securityConfig["certificate_chain_validation"].(bool) {
		return fmt.Errorf("certificate chain validation must be enabled")
	}

	return nil
}

func createDirectories(config *utils.Config) error {
	dirs := []string{
		config.KeysPath,
		config.CertificatesPath,
		config.BackupPath,
		config.LogsPath,
		"./data",
		"./web/static",
		"./web/templates",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	restrictedDirs := []string{config.KeysPath}
	for _, dir := range restrictedDirs {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("failed to set secure permissions on %s: %v", dir, err)
		}
	}

	return nil
}

func validateCAs(rootCA *ca.RootCA, intermediateCA *ca.IntermediateCA) error {
	fmt.Println("Validating Root CA integrity...")
	if err := rootCA.ValidateIntegrity(); err != nil {
		return fmt.Errorf("root CA integrity check failed: %w", err)
	}

	fmt.Println("Validating Intermediate CA integrity...")
	if err := intermediateCA.ValidateIntegrity(); err != nil {
		return fmt.Errorf("intermediate CA integrity check failed: %w", err)
	}

	fmt.Println("Validating certificate chain...")
	if intermediateCA.GetCertificate() == nil {
		return fmt.Errorf("intermediate CA certificate not found")
	}

	if err := rootCA.ValidateCertificateChain(intermediateCA.GetCertificate()); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	fmt.Println("✅ All CA validations passed")
	return nil
}

func printSecurityInfo(config *utils.Config) {
	fmt.Println("\n🔒 Security Configuration:")
	fmt.Printf("   • Key Encryption: %t\n", config.KeyEncryptionEnabled)
	fmt.Printf("   • Domain Validation: %t\n", config.DomainValidationRequired)
	fmt.Printf("   • Chain Validation: %t\n", config.CertificateChainValidation)
	fmt.Printf("   • TLS Enabled: %t\n", config.TLSEnabled)
	fmt.Printf("   • Environment: %s\n", config.Environment)

	if config.IsProduction() {
		fmt.Println("\n⚠️  Production Environment Detected:")
		fmt.Println("   • Ensure TLS certificates are properly configured")
		fmt.Println("   • Monitor certificate expiration dates")
		fmt.Println("   • Regularly backup encrypted keys")
		fmt.Println("   • Review audit logs frequently")
	}

	fmt.Println("\n📝 Next Steps:")
	fmt.Println("   1. Configure your domain validation (DNS/HTTP)")
	fmt.Println("   2. Set up monitoring and alerting")
	fmt.Println("   3. Configure backup encryption")
	fmt.Println("   4. Review security policies")
}