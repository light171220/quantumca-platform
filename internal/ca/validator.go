package ca

import (
	"fmt"
	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/utils"
)

type CertificateValidator struct {
	config           *utils.Config
	logger           *utils.Logger
	allowedAlgorithms map[string]bool
}

func NewCertificateValidator(config *utils.Config, logger *utils.Logger) *CertificateValidator {
	allowedAlgs := map[string]bool{
		"dilithium2":            true,
		"dilithium3":            true,
		"dilithium5":            true,
		"falcon512":             true,
		"falcon1024":            true,
		"sphincs-sha256-128f":   true,
		"sphincs-sha256-128s":   true,
		"sphincs-sha256-192f":   true,
		"sphincs-sha256-256f":   true,
		"kyber512":              true,
		"kyber768":              true,
		"kyber1024":             true,
	}

	return &CertificateValidator{
		config:           config,
		logger:           logger,
		allowedAlgorithms: allowedAlgs,
	}
}

func (cv *CertificateValidator) IsAlgorithmAllowed(algorithm string) bool {
	return cv.allowedAlgorithms[algorithm]
}

func (cv *CertificateValidator) ValidateKeyPair(privateKey, publicKey interface{}) error {
	return pq.ValidateKeyPair(privateKey, publicKey)
}

func (cv *CertificateValidator) ValidateAlgorithmSupported(algorithm string) error {
	if !cv.IsAlgorithmAllowed(algorithm) {
		return fmt.Errorf("algorithm %s is not supported", algorithm)
	}
	return nil
}