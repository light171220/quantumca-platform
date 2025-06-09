package utils

import (
	"os"
	"strconv"
)

type Config struct {
	DatabasePath                string
	KeysPath                    string
	CertificatesPath            string
	RootCAPassphrase            string
	IntermediateCAPassphrase    string
	OCSPPort                    int
	LogLevel                    string
	DomainValidationTimeout     int
	CertificateValidityDays     int
	IntermediateCAValidityDays  int
	RootCAValidityDays          int
}

func LoadConfig() (*Config, error) {
	config := &Config{
		DatabasePath:                getEnv("DATABASE_PATH", "./data/database.db"),
		KeysPath:                    getEnv("KEYS_PATH", "./data/keys"),
		CertificatesPath:            getEnv("CERTIFICATES_PATH", "./data/certificates"),
		RootCAPassphrase:            getEnv("ROOT_CA_PASSPHRASE", "changeme"),
		IntermediateCAPassphrase:    getEnv("INTERMEDIATE_CA_PASSPHRASE", "changeme"),
		LogLevel:                    getEnv("LOG_LEVEL", "info"),
		OCSPPort:                    getEnvInt("OCSP_PORT", 8081),
		DomainValidationTimeout:     getEnvInt("DOMAIN_VALIDATION_TIMEOUT", 300),
		CertificateValidityDays:     getEnvInt("CERTIFICATE_VALIDITY_DAYS", 365),
		IntermediateCAValidityDays:  getEnvInt("INTERMEDIATE_CA_VALIDITY_DAYS", 1825),
		RootCAValidityDays:          getEnvInt("ROOT_CA_VALIDITY_DAYS", 7300),
	}

	return config, nil
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