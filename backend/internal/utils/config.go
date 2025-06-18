package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment                 string
	DatabasePath                string
	KeysPath                    string
	CertificatesPath            string
	BackupPath                  string
	LogsPath                    string
	RootCAPassphrase            string
	IntermediateCAPassphrase    string
	OCSPPort                    int
	APIPort                     int
	MetricsPort                 int
	LogLevel                    string
	DomainValidationTimeout     time.Duration
	CertificateValidityDays     int
	IntermediateCAValidityDays  int
	RootCAValidityDays          int
	JWTSecret                   string
	JWTExpirationHours          int
	APIRateLimit                int
	APIRateBurst                int
	MaxCertificateSize          int64
	MaxCertificatesPerCustomer  int
	BackupEnabled               bool
	BackupInterval              time.Duration
	BackupRetentionDays         int
	CertificateCleanupInterval  time.Duration
	MetricsEnabled              bool
	HealthCheckInterval         time.Duration
	DatabaseMaxConnections      int
	DatabaseMaxIdleConnections  int
	DatabaseConnectionMaxLife   time.Duration
	TLSEnabled                  bool
	TLSCertPath                 string
	TLSKeyPath                  string
	AllowedOrigins              []string
	MaxRequestSize              int64
	ReadTimeout                 time.Duration
	WriteTimeout                time.Duration
	IdleTimeout                 time.Duration
	GracefulShutdownTimeout     time.Duration
	EnableProfiling             bool
	SecretRotationInterval      time.Duration
	AuditLogRetentionDays       int
	CertificateRenewalDays      int
	ValidationConcurrency       int
	CacheEnabled                bool
	CacheTTL                    time.Duration
	ComplianceMode              bool
	FIPSMode                    bool
	KeyEncryptionEnabled        bool
	DomainValidationRequired    bool
	CertificateChainValidation  bool
	BackupEncryptionPassword    string
	EnableMultiPQC              bool
	DefaultMultiPQCAlgorithms   []string
	MinSecurityLevel            int
	AllowedAlgorithms           []string
}

func LoadConfig() (*Config, error) {
	config := &Config{
		Environment:                 getEnv("ENVIRONMENT", "development"),
		DatabasePath:                getEnv("DATABASE_PATH", "./data/database.db"),
		KeysPath:                    getEnv("KEYS_PATH", "./data/keys"),
		CertificatesPath:            getEnv("CERTIFICATES_PATH", "./data/certificates"),
		BackupPath:                  getEnv("BACKUP_PATH", "./data/backups"),
		LogsPath:                    getEnv("LOGS_PATH", "./data/logs"),
		LogLevel:                    getEnv("LOG_LEVEL", "info"),
		APIPort:                     getEnvInt("API_PORT", 8080),
		OCSPPort:                    getEnvInt("OCSP_PORT", 8081),
		MetricsPort:                 getEnvInt("METRICS_PORT", 9090),
		DomainValidationTimeout:     getEnvDuration("DOMAIN_VALIDATION_TIMEOUT", "5m"),
		CertificateValidityDays:     getEnvInt("CERTIFICATE_VALIDITY_DAYS", 365),
		IntermediateCAValidityDays:  getEnvInt("INTERMEDIATE_CA_VALIDITY_DAYS", 1825),
		RootCAValidityDays:          getEnvInt("ROOT_CA_VALIDITY_DAYS", 7300),
		JWTExpirationHours:          getEnvInt("JWT_EXPIRATION_HOURS", 24),
		APIRateLimit:                getEnvInt("API_RATE_LIMIT", 100),
		APIRateBurst:                getEnvInt("API_RATE_BURST", 50),
		MaxCertificateSize:          getEnvInt64("MAX_CERTIFICATE_SIZE", 1024*1024),
		MaxCertificatesPerCustomer:  getEnvInt("MAX_CERTIFICATES_PER_CUSTOMER", 1000),
		BackupEnabled:               getEnvBool("BACKUP_ENABLED", true),
		BackupInterval:              getEnvDuration("BACKUP_INTERVAL", "24h"),
		BackupRetentionDays:         getEnvInt("BACKUP_RETENTION_DAYS", 30),
		CertificateCleanupInterval:  getEnvDuration("CERTIFICATE_CLEANUP_INTERVAL", "1h"),
		MetricsEnabled:              getEnvBool("METRICS_ENABLED", true),
		HealthCheckInterval:         getEnvDuration("HEALTH_CHECK_INTERVAL", "30s"),
		DatabaseMaxConnections:      getEnvInt("DATABASE_MAX_CONNECTIONS", 25),
		DatabaseMaxIdleConnections:  getEnvInt("DATABASE_MAX_IDLE_CONNECTIONS", 5),
		DatabaseConnectionMaxLife:   getEnvDuration("DATABASE_CONNECTION_MAX_LIFE", "5m"),
		TLSEnabled:                  getEnvBool("TLS_ENABLED", false),
		TLSCertPath:                 getEnv("TLS_CERT_PATH", ""),
		TLSKeyPath:                  getEnv("TLS_KEY_PATH", ""),
		MaxRequestSize:              getEnvInt64("MAX_REQUEST_SIZE", 10*1024*1024),
		ReadTimeout:                 getEnvDuration("READ_TIMEOUT", "30s"),
		WriteTimeout:                getEnvDuration("WRITE_TIMEOUT", "30s"),
		IdleTimeout:                 getEnvDuration("IDLE_TIMEOUT", "120s"),
		GracefulShutdownTimeout:     getEnvDuration("GRACEFUL_SHUTDOWN_TIMEOUT", "30s"),
		EnableProfiling:             getEnvBool("ENABLE_PROFILING", false),
		SecretRotationInterval:      getEnvDuration("SECRET_ROTATION_INTERVAL", "720h"),
		AuditLogRetentionDays:       getEnvInt("AUDIT_LOG_RETENTION_DAYS", 90),
		CertificateRenewalDays:      getEnvInt("CERTIFICATE_RENEWAL_DAYS", 30),
		ValidationConcurrency:       getEnvInt("VALIDATION_CONCURRENCY", 10),
		CacheEnabled:                getEnvBool("CACHE_ENABLED", true),
		CacheTTL:                    getEnvDuration("CACHE_TTL", "1h"),
		ComplianceMode:              getEnvBool("COMPLIANCE_MODE", false),
		FIPSMode:                    getEnvBool("FIPS_MODE", false),
		KeyEncryptionEnabled:        getEnvBool("KEY_ENCRYPTION_ENABLED", true),
		DomainValidationRequired:    getEnvBool("DOMAIN_VALIDATION_REQUIRED", true),
		CertificateChainValidation:  getEnvBool("CERTIFICATE_CHAIN_VALIDATION", true),
		EnableMultiPQC:              getEnvBool("ENABLE_MULTI_PQC", true),
		DefaultMultiPQCAlgorithms:   []string{"dilithium3", "falcon1024", "sphincs-sha256-256f"},
		MinSecurityLevel:            getEnvInt("MIN_SECURITY_LEVEL", 128),
		AllowedAlgorithms: []string{
			"dilithium2", "dilithium3", "dilithium5",
			"falcon512", "falcon1024",
			"sphincs-sha256-128f", "sphincs-sha256-128s",
			"sphincs-sha256-192f", "sphincs-sha256-256f",
			"kyber512", "kyber768", "kyber1024",
			"multi-pqc",
		},
	}

	if err := config.loadSecrets(); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	if err := config.loadAllowedOrigins(); err != nil {
		return nil, fmt.Errorf("failed to load allowed origins: %w", err)
	}

	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	if err := config.createDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return config, nil
}

func (c *Config) loadSecrets() error {
	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		var err error
		jwtSecret, err = generateRandomSecret(64)
		if err != nil {
			return fmt.Errorf("failed to generate JWT secret: %w", err)
		}
	}
	c.JWTSecret = jwtSecret

	rootCAPassphrase := getEnv("ROOT_CA_PASSPHRASE", "")
	if rootCAPassphrase == "" {
		var err error
		rootCAPassphrase, err = generateRandomSecret(32)
		if err != nil {
			return fmt.Errorf("failed to generate root CA passphrase: %w", err)
		}
	}
	c.RootCAPassphrase = rootCAPassphrase

	intermediateCAPassphrase := getEnv("INTERMEDIATE_CA_PASSPHRASE", "")
	if intermediateCAPassphrase == "" {
		var err error
		intermediateCAPassphrase, err = generateRandomSecret(32)
		if err != nil {
			return fmt.Errorf("failed to generate intermediate CA passphrase: %w", err)
		}
	}
	c.IntermediateCAPassphrase = intermediateCAPassphrase

	backupPassword := getEnv("BACKUP_ENCRYPTION_PASSWORD", "")
	if backupPassword == "" {
		var err error
		backupPassword, err = generateRandomSecret(32)
		if err != nil {
			return fmt.Errorf("failed to generate backup encryption password: %w", err)
		}
	}
	c.BackupEncryptionPassword = backupPassword

	return nil
}

func (c *Config) loadAllowedOrigins() error {
	originsStr := getEnv("ALLOWED_ORIGINS", "")
	if originsStr == "" {
		c.AllowedOrigins = []string{
			"https://localhost:3000",
			"https://127.0.0.1:3000",
		}
		if c.Environment == "development" {
			c.AllowedOrigins = append(c.AllowedOrigins,
				"http://localhost:3000",
				"http://127.0.0.1:3000",
			)
		}
	} else {
		c.AllowedOrigins = strings.Split(originsStr, ",")
		for i, origin := range c.AllowedOrigins {
			c.AllowedOrigins[i] = strings.TrimSpace(origin)
		}
	}
	return nil
}

func (c *Config) validate() error {
	if c.Environment != "development" && c.Environment != "staging" && c.Environment != "production" {
		return fmt.Errorf("invalid environment: %s", c.Environment)
	}

	if c.APIPort < 1 || c.APIPort > 65535 {
		return fmt.Errorf("invalid API port: %d", c.APIPort)
	}

	if c.OCSPPort < 1 || c.OCSPPort > 65535 {
		return fmt.Errorf("invalid OCSP port: %d", c.OCSPPort)
	}

	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return fmt.Errorf("invalid metrics port: %d", c.MetricsPort)
	}

	if c.CertificateValidityDays < 1 || c.CertificateValidityDays > 3650 {
		return fmt.Errorf("invalid certificate validity days: %d", c.CertificateValidityDays)
	}

	if c.IntermediateCAValidityDays < 365 || c.IntermediateCAValidityDays > 7300 {
		return fmt.Errorf("invalid intermediate CA validity days: %d", c.IntermediateCAValidityDays)
	}

	if c.RootCAValidityDays < 1825 || c.RootCAValidityDays > 10950 {
		return fmt.Errorf("invalid root CA validity days: %d", c.RootCAValidityDays)
	}

	if c.APIRateLimit < 1 || c.APIRateLimit > 10000 {
		return fmt.Errorf("invalid API rate limit: %d", c.APIRateLimit)
	}

	if c.MaxCertificatesPerCustomer < 1 || c.MaxCertificatesPerCustomer > 100000 {
		return fmt.Errorf("invalid max certificates per customer: %d", c.MaxCertificatesPerCustomer)
	}

	if c.TLSEnabled && (c.TLSCertPath == "" || c.TLSKeyPath == "") {
		return fmt.Errorf("TLS enabled but cert or key path not specified")
	}

	if c.DomainValidationTimeout < time.Minute || c.DomainValidationTimeout > time.Hour {
		return fmt.Errorf("invalid domain validation timeout: %v", c.DomainValidationTimeout)
	}

	logLevels := []string{"debug", "info", "warn", "error", "fatal"}
	validLogLevel := false
	for _, level := range logLevels {
		if c.LogLevel == level {
			validLogLevel = true
			break
		}
	}
	if !validLogLevel {
		return fmt.Errorf("invalid log level: %s", c.LogLevel)
	}

	if c.KeyEncryptionEnabled && (c.RootCAPassphrase == "" || c.IntermediateCAPassphrase == "") {
		return fmt.Errorf("key encryption enabled but passphrases not configured")
	}

	if len(c.RootCAPassphrase) < 32 {
		return fmt.Errorf("root CA passphrase must be at least 32 characters")
	}

	if len(c.IntermediateCAPassphrase) < 32 {
		return fmt.Errorf("intermediate CA passphrase must be at least 32 characters")
	}

	if c.EnableMultiPQC && len(c.DefaultMultiPQCAlgorithms) < 3 {
		return fmt.Errorf("multi-PQC requires at least 3 algorithms")
	}

	if c.MinSecurityLevel < 128 {
		return fmt.Errorf("minimum security level must be at least 128 bits")
	}

	return nil
}

func (c *Config) createDirectories() error {
	dirs := []string{
		c.KeysPath,
		c.CertificatesPath,
		c.BackupPath,
		c.LogsPath,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	restrictedDirs := []string{c.KeysPath}
	for _, dir := range restrictedDirs {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("failed to set permissions on %s: %w", dir, err)
		}
	}

	return nil
}

func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

func (c *Config) GetDefaultAlgorithm() string {
	if c.EnableMultiPQC {
		return "multi-pqc"
	}
	return "dilithium3"
}

func (c *Config) GetMultiPQCAlgorithms() []string {
	return c.DefaultMultiPQCAlgorithms
}

func (c *Config) IsAlgorithmAllowed(algorithm string) bool {
	for _, allowed := range c.AllowedAlgorithms {
		if algorithm == allowed {
			return true
		}
	}
	return false
}

func (c *Config) GetDatabaseConfig() map[string]interface{} {
	return map[string]interface{}{
		"path":                 c.DatabasePath,
		"max_connections":      c.DatabaseMaxConnections,
		"max_idle_connections": c.DatabaseMaxIdleConnections,
		"connection_max_life":  c.DatabaseConnectionMaxLife,
	}
}

func (c *Config) GetTLSConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":   c.TLSEnabled,
		"cert_path": c.TLSCertPath,
		"key_path":  c.TLSKeyPath,
	}
}

func (c *Config) GetRateLimitConfig() map[string]interface{} {
	return map[string]interface{}{
		"limit": c.APIRateLimit,
		"burst": c.APIRateBurst,
	}
}

func (c *Config) GetSecurityConfig() map[string]interface{} {
	return map[string]interface{}{
		"key_encryption_enabled":       c.KeyEncryptionEnabled,
		"domain_validation_required":   c.DomainValidationRequired,
		"certificate_chain_validation": c.CertificateChainValidation,
		"compliance_mode":              c.ComplianceMode,
		"fips_mode":                    c.FIPSMode,
		"enable_multi_pqc":             c.EnableMultiPQC,
		"min_security_level":           c.MinSecurityLevel,
	}
}

func (c *Config) ValidateSecuritySettings() error {
	if !c.KeyEncryptionEnabled {
		return fmt.Errorf("key encryption must be enabled in production")
	}

	if !c.DomainValidationRequired {
		return fmt.Errorf("domain validation must be enabled in production")
	}

	if !c.CertificateChainValidation {
		return fmt.Errorf("certificate chain validation must be enabled in production")
	}

	if c.IsProduction() && !c.TLSEnabled {
		return fmt.Errorf("TLS must be enabled in production")
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue string) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	duration, _ := time.ParseDuration(defaultValue)
	return duration
}

func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}