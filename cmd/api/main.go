package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"quantumca-platform/internal/api"
	"quantumca-platform/internal/ocsp"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

func main() {
	fmt.Println("🚀 Starting QuantumCA Platform API Server...")

	config, err := utils.LoadConfig()
	if err != nil {
		log.Fatal("❌ Failed to load config:", err)
	}

	logger := utils.NewLogger(config.LogLevel)

	if err := validateStartupConfig(config, logger); err != nil {
		logger.Fatal("❌ Startup validation failed:", err)
	}

	db, err := storage.NewSQLiteDB(config.DatabasePath)
	if err != nil {
		logger.Fatal("❌ Failed to connect to database:", err)
	}
	defer db.Close()

	if err := storage.RunMigrations(db); err != nil {
		logger.Fatal("❌ Failed to run migrations:", err)
	}

	logger.Info("🔐 Initializing OCSP responder with encrypted key storage...")
	ocspServer := ocsp.NewServer(db, config)
	
	go func() {
		logger.Infof("🌐 Starting OCSP server on port %d", config.OCSPPort)
		if err := ocspServer.Start(); err != nil {
			logger.Error("❌ OCSP server failed:", err)
		}
	}()

	logger.Info("🏗️  Initializing API server with security validations...")
	server, err := api.NewServer(db, config, logger)
	if err != nil {
		logger.Fatal("❌ Failed to create API server:", err)
	}

	logger.Info("✅ QuantumCA Platform initialized successfully")
	printStartupInfo(config, logger)

	go func() {
		logger.Infof("🌐 Starting API server on port %d", config.APIPort)
		if err := server.Start(); err != nil {
			logger.Fatal("❌ Server failed to start:", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	
	sig := <-quit
	logger.Infof("📡 Received signal %v, initiating graceful shutdown...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), config.GracefulShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(); err != nil {
		logger.Error("❌ Server shutdown error:", err)
	}

	select {
	case <-shutdownCtx.Done():
		logger.Warn("⏰ Shutdown timeout exceeded, forcing exit")
	default:
		logger.Info("✅ Server shutdown completed successfully")
	}
}

func validateStartupConfig(config *utils.Config, logger *utils.Logger) error {
	logger.Info("🔍 Validating security configuration...")

	if err := config.ValidateSecuritySettings(); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	securityConfig := config.GetSecurityConfig()
	
	if !securityConfig["key_encryption_enabled"].(bool) {
		return fmt.Errorf("key encryption is disabled - this is not secure for production")
	}

	if !securityConfig["domain_validation_required"].(bool) {
		logger.Warn("⚠️  Domain validation is disabled - certificates may be issued for uncontrolled domains")
	}

	if !securityConfig["certificate_chain_validation"].(bool) {
		return fmt.Errorf("certificate chain validation is disabled - this could allow invalid certificates")
	}

	if config.IsProduction() {
		if !config.TLSEnabled {
			return fmt.Errorf("TLS must be enabled in production environment")
		}

		if config.LogLevel == "debug" {
			logger.Warn("⚠️  Debug logging enabled in production - consider changing to 'info' or 'warn'")
		}
	}

	if !fileExists(config.KeysPath) {
		return fmt.Errorf("keys directory does not exist: %s", config.KeysPath)
	}

	if !fileExists(config.DatabasePath) {
		logger.Info("📄 Database file not found, will be created during migration")
	}

	logger.Info("✅ Security configuration validation passed")
	return nil
}

func printStartupInfo(config *utils.Config, logger *utils.Logger) {
	logger.Info("🔐 Security Features Enabled:")
	logger.Infof("   • Encrypted Key Storage: %t", config.KeyEncryptionEnabled)
	logger.Infof("   • Domain Validation: %t", config.DomainValidationRequired)
	logger.Infof("   • Certificate Chain Validation: %t", config.CertificateChainValidation)
	logger.Infof("   • TLS Encryption: %t", config.TLSEnabled)
	logger.Infof("   • Rate Limiting: %d req/min", config.APIRateLimit)

	logger.Info("📊 Service Configuration:")
	logger.Infof("   • Environment: %s", config.Environment)
	logger.Infof("   • API Port: %d", config.APIPort)
	logger.Infof("   • OCSP Port: %d", config.OCSPPort)
	logger.Infof("   • Metrics Port: %d", config.MetricsPort)
	logger.Infof("   • Log Level: %s", config.LogLevel)

	if config.BackupEnabled {
		logger.Infof("💾 Backup System: Enabled (every %v)", config.BackupInterval)
	}

	if config.MetricsEnabled {
		logger.Info("📈 Metrics Collection: Enabled")
	}

	if config.IsProduction() {
		logger.Info("🏭 Production Environment - All security features active")
	} else {
		logger.Info("🧪 Development Environment - Some security features may be relaxed")
	}

	logger.Info("🌐 API Endpoints Available:")
	logger.Info("   • Certificate Management: /api/v1/certificates")
	logger.Info("   • Domain Validation: /api/v1/domains")
	logger.Info("   • Customer Management: /api/v1/customers")
	logger.Info("   • Health Checks: /health")
	logger.Info("   • Metrics: /health/metrics")
	logger.Info("   • OCSP Responder: Port " + fmt.Sprintf("%d", config.OCSPPort))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}