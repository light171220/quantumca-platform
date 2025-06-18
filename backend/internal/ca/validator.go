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
		"multi-pqc":             true,
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

func (cv *CertificateValidator) ValidateMultiPQCKeyPair(multiPQCPrivateKey *pq.MultiPQCPrivateKey) error {
	if multiPQCPrivateKey == nil {
		return fmt.Errorf("multi-PQC private key cannot be nil")
	}

	multiPQCPublicKey, err := multiPQCPrivateKey.Public()
	if err != nil {
		return fmt.Errorf("failed to get multi-PQC public key: %w", err)
	}

	testMessage := []byte("multi-pqc-validation-test")
	signature, err := multiPQCPrivateKey.Sign(testMessage)
	if err != nil {
		return fmt.Errorf("failed to sign with multi-PQC key: %w", err)
	}

	if !multiPQCPublicKey.Verify(testMessage, signature) {
		return fmt.Errorf("multi-PQC signature verification failed")
	}

	if err := pq.ValidateKeyPair(multiPQCPrivateKey.PrimaryKey, multiPQCPublicKey.PrimaryKey); err != nil {
		return fmt.Errorf("primary key pair validation failed: %w", err)
	}

	if err := pq.ValidateKeyPair(multiPQCPrivateKey.SecondaryKey, multiPQCPublicKey.SecondaryKey); err != nil {
		return fmt.Errorf("secondary key pair validation failed: %w", err)
	}

	if err := pq.ValidateKeyPair(multiPQCPrivateKey.TertiaryKey, multiPQCPublicKey.TertiaryKey); err != nil {
		return fmt.Errorf("tertiary key pair validation failed: %w", err)
	}

	return nil
}

func (cv *CertificateValidator) ValidateAlgorithmSupported(algorithm string) error {
	if !cv.IsAlgorithmAllowed(algorithm) {
		return fmt.Errorf("algorithm %s is not supported", algorithm)
	}
	return nil
}

func (cv *CertificateValidator) ValidateMultiPQCAlgorithms(algorithms []string) error {
	if len(algorithms) < 3 {
		return fmt.Errorf("multi-PQC requires at least 3 algorithms")
	}

	for _, algorithm := range algorithms {
		if algorithm == "multi-pqc" {
			continue
		}
		if !pq.IsSignatureAlgorithm(algorithm) {
			return fmt.Errorf("algorithm %s is not a signature algorithm", algorithm)
		}
		if !cv.IsAlgorithmAllowed(algorithm) {
			return fmt.Errorf("algorithm %s is not allowed", algorithm)
		}
	}

	expectedAlgorithms := map[string]bool{
		"dilithium3":           false,
		"falcon1024":           false,
		"sphincs-sha256-256f":  false,
	}

	for _, algorithm := range algorithms {
		if _, exists := expectedAlgorithms[algorithm]; exists {
			expectedAlgorithms[algorithm] = true
		}
	}

	for algorithm, found := range expectedAlgorithms {
		if !found {
			return fmt.Errorf("missing required multi-PQC algorithm: %s", algorithm)
		}
	}

	return nil
}

func (cv *CertificateValidator) ValidateSignatureStrength(algorithm string) error {
	strengthMap := map[string]int{
		"dilithium2":            128,
		"dilithium3":            192,
		"dilithium5":            256,
		"falcon512":             128,
		"falcon1024":            256,
		"sphincs-sha256-128f":   128,
		"sphincs-sha256-128s":   128,
		"sphincs-sha256-192f":   192,
		"sphincs-sha256-256f":   256,
		"multi-pqc":             256,
	}

	strength, exists := strengthMap[algorithm]
	if !exists {
		return fmt.Errorf("unknown algorithm strength for %s", algorithm)
	}

	minStrength := 128
	if cv.config.MinSecurityLevel > 0 {
		minStrength = cv.config.MinSecurityLevel
	}

	if strength < minStrength {
		return fmt.Errorf("algorithm %s provides %d-bit security, minimum required is %d-bit", algorithm, strength, minStrength)
	}

	return nil
}

func (cv *CertificateValidator) ValidateAlgorithmCombination(algorithms []string) error {
	if len(algorithms) == 0 {
		return fmt.Errorf("no algorithms specified")
	}

	hasMultiPQC := false
	hasSignature := false

	for _, algorithm := range algorithms {
		if algorithm == "multi-pqc" {
			hasMultiPQC = true
			hasSignature = true
			continue
		}

		if pq.IsSignatureAlgorithm(algorithm) {
			hasSignature = true
		}
	}

	if !hasSignature {
		return fmt.Errorf("at least one signature algorithm is required")
	}

	if hasMultiPQC && len(algorithms) < 4 {
		return fmt.Errorf("multi-PQC requires additional component algorithms")
	}

	return nil
}

func (cv *CertificateValidator) ValidateKeySize(algorithm string, keySize int) error {
	expectedSizes := map[string][]int{
		"dilithium2":            {2560, 1312},
		"dilithium3":            {4000, 1952},
		"dilithium5":            {4864, 2592},
		"falcon512":             {1281, 897},
		"falcon1024":            {2305, 1793},
		"sphincs-sha256-128f":   {64, 32},
		"sphincs-sha256-128s":   {64, 32},
		"sphincs-sha256-192f":   {96, 48},
		"sphincs-sha256-256f":   {128, 64},
		"kyber512":              {1632, 800},
		"kyber768":              {2400, 1184},
		"kyber1024":             {3168, 1568},
	}

	sizes, exists := expectedSizes[algorithm]
	if !exists {
		return fmt.Errorf("unknown algorithm: %s", algorithm)
	}

	validSize := false
	for _, size := range sizes {
		if keySize == size {
			validSize = true
			break
		}
	}

	if !validSize {
		return fmt.Errorf("invalid key size %d for algorithm %s, expected one of %v", keySize, algorithm, sizes)
	}

	return nil
}

func (cv *CertificateValidator) ValidateCertificatePolicy(algorithms []string, isCA bool) error {
	if isCA {
		hasStrongSignature := false
		for _, algorithm := range algorithms {
			if algorithm == "multi-pqc" || algorithm == "dilithium5" || algorithm == "falcon1024" || algorithm == "sphincs-sha256-256f" {
				hasStrongSignature = true
				break
			}
		}
		if !hasStrongSignature {
			return fmt.Errorf("CA certificates require strong signature algorithms")
		}
	}

	return nil
}