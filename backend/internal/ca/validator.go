package ca

import (
	"context"
	"fmt"
	"sync"
	"time"
	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/utils"
)

type CertificateValidator struct {
	config            *utils.Config
	logger            *utils.Logger
	allowedAlgorithms map[string]bool
	maxWorkers        int
}

type validationTask struct {
	privateKey interface{}
	publicKey  interface{}
	algorithm  string
	index      int
	result     chan validationResult
}

type validationResult struct {
	index int
	error error
}

type algorithmValidationResult struct {
	algorithm string
	valid     bool
	error     error
}

func NewCertificateValidator(config *utils.Config, logger *utils.Logger) *CertificateValidator {
	allowedAlgs := map[string]bool{
		"dilithium2":            true,
		"dilithium3":            true,
		"dilithium5":            true,
		"sphincs-sha256-128f":   true,
		"sphincs-sha256-128s":   true,
		"sphincs-sha256-192f":   true,
		"sphincs-sha256-256f":   true,
		"kyber512":              true,
		"kyber768":              true,
		"kyber1024":             true,
		"multi-pqc":             true,
	}

	maxWorkers := 10
	if config.MaxWorkers > 0 {
		maxWorkers = config.MaxWorkers
	}

	return &CertificateValidator{
		config:            config,
		logger:            logger,
		allowedAlgorithms: allowedAlgs,
		maxWorkers:        maxWorkers,
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	multiPQCPublicKey, err := multiPQCPrivateKey.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get multi-PQC public key: %w", err)
	}

	testMessage := []byte("multi-pqc-validation-test")
	signature, err := multiPQCPrivateKey.SignMessageWithTimeout(testMessage, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to sign with multi-PQC key: %w", err)
	}

	if !multiPQCPublicKey.VerifyWithTimeout(testMessage, signature, 10*time.Second) {
		return fmt.Errorf("multi-PQC signature verification failed")
	}

	return cv.validateIndividualKeyPairsParallel(ctx, multiPQCPrivateKey, multiPQCPublicKey)
}

func (cv *CertificateValidator) validateIndividualKeyPairsParallel(ctx context.Context, privateKey *pq.MultiPQCPrivateKey, publicKey *pq.MultiPQCPublicKey) error {
	type keyPair struct {
		private interface{}
		public  interface{}
		name    string
	}

	keyPairs := []keyPair{
		{privateKey.PrimaryKey, publicKey.PrimaryKey, "primary"},
		{privateKey.SecondaryKey, publicKey.SecondaryKey, "secondary"},
		{privateKey.TertiaryKey, publicKey.TertiaryKey, "tertiary"},
	}

	resultChan := make(chan validationResult, len(keyPairs))
	var wg sync.WaitGroup

	for i, kp := range keyPairs {
		wg.Add(1)
		go func(index int, pair keyPair) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- validationResult{index: index, error: ctx.Err()}
				return
			default:
			}
			
			if err := pq.ValidateKeyPair(pair.private, pair.public); err != nil {
				resultChan <- validationResult{index: index, error: fmt.Errorf("%s key pair validation failed: %w", pair.name, err)}
				return
			}
			
			resultChan <- validationResult{index: index, error: nil}
		}(i, kp)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.error != nil {
			return result.error
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return cv.validateAlgorithmsParallel(ctx, algorithms)
}

func (cv *CertificateValidator) validateAlgorithmsParallel(ctx context.Context, algorithms []string) error {
	resultChan := make(chan algorithmValidationResult, len(algorithms))
	var wg sync.WaitGroup

	for _, algorithm := range algorithms {
		wg.Add(1)
		go func(alg string) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- algorithmValidationResult{algorithm: alg, valid: false, error: ctx.Err()}
				return
			default:
			}
			
			if alg == "multi-pqc" {
				resultChan <- algorithmValidationResult{algorithm: alg, valid: true, error: nil}
				return
			}
			
			if !pq.IsSignatureAlgorithm(alg) {
				resultChan <- algorithmValidationResult{algorithm: alg, valid: false, error: fmt.Errorf("algorithm %s is not a signature algorithm", alg)}
				return
			}
			
			if !cv.IsAlgorithmAllowed(alg) {
				resultChan <- algorithmValidationResult{algorithm: alg, valid: false, error: fmt.Errorf("algorithm %s is not allowed", alg)}
				return
			}
			
			resultChan <- algorithmValidationResult{algorithm: alg, valid: true, error: nil}
		}(algorithm)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	expectedAlgorithms := map[string]bool{
		"dilithium3":            false,
		"sphincs-sha256-128s":   false,
		"dilithium5":            false,
	}

	for result := range resultChan {
		if result.error != nil {
			return result.error
		}
		
		if !result.valid {
			return fmt.Errorf("algorithm validation failed for %s", result.algorithm)
		}
		
		if _, exists := expectedAlgorithms[result.algorithm]; exists {
			expectedAlgorithms[result.algorithm] = true
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return cv.validateCombinationParallel(ctx, algorithms)
}

func (cv *CertificateValidator) validateCombinationParallel(ctx context.Context, algorithms []string) error {
	type combinationResult struct {
		hasMultiPQC  bool
		hasSignature bool
		error        error
	}

	resultChan := make(chan combinationResult, 1)
	
	go func() {
		defer close(resultChan)
		
		select {
		case <-ctx.Done():
			resultChan <- combinationResult{error: ctx.Err()}
			return
		default:
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
		
		result := combinationResult{
			hasMultiPQC:  hasMultiPQC,
			hasSignature: hasSignature,
		}
		
		if !hasSignature {
			result.error = fmt.Errorf("at least one signature algorithm is required")
		} else if hasMultiPQC && len(algorithms) < 4 {
			result.error = fmt.Errorf("multi-PQC requires additional component algorithms")
		}
		
		resultChan <- result
	}()

	result := <-resultChan
	return result.error
}

func (cv *CertificateValidator) ValidateKeySize(algorithm string, keySize int) error {
	expectedSizes := map[string][]int{
		"dilithium2":            {2560, 1312},
		"dilithium3":            {4000, 1952},
		"dilithium5":            {4864, 2592},
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
	if !isCA {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return cv.validateCAPolicyParallel(ctx, algorithms)
}

func (cv *CertificateValidator) validateCAPolicyParallel(ctx context.Context, algorithms []string) error {
	resultChan := make(chan bool, 1)
	
	go func() {
		defer close(resultChan)
		
		select {
		case <-ctx.Done():
			resultChan <- false
			return
		default:
		}
		
		hasStrongSignature := false
		for _, algorithm := range algorithms {
			if algorithm == "multi-pqc" || algorithm == "dilithium5" || algorithm == "sphincs-sha256-256f" {
				hasStrongSignature = true
				break
			}
		}
		
		resultChan <- hasStrongSignature
	}()

	hasStrongSignature := <-resultChan
	if !hasStrongSignature {
		return fmt.Errorf("CA certificates require strong signature algorithms")
	}

	return nil
}

func (cv *CertificateValidator) ValidateMultipleCertificates(certificates [][]byte) error {
	if len(certificates) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(certificates))*10*time.Second)
	defer cancel()

	return cv.validateCertificatesParallel(ctx, certificates)
}

func (cv *CertificateValidator) validateCertificatesParallel(ctx context.Context, certificates [][]byte) error {
	numWorkers := cv.maxWorkers
	if numWorkers > len(certificates) {
		numWorkers = len(certificates)
	}

	certChan := make(chan struct{
		data  []byte
		index int
	}, len(certificates))
	
	resultChan := make(chan validationResult, len(certificates))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for cert := range certChan {
				select {
				case <-ctx.Done():
					resultChan <- validationResult{index: cert.index, error: ctx.Err()}
					return
				default:
				}
				
				if err := cv.validateSingleCertificate(cert.data); err != nil {
					resultChan <- validationResult{index: cert.index, error: fmt.Errorf("certificate %d validation failed: %w", cert.index, err)}
					continue
				}
				
				resultChan <- validationResult{index: cert.index, error: nil}
			}
		}()
	}

	for i, certData := range certificates {
		certChan <- struct {
			data  []byte
			index int
		}{data: certData, index: i}
	}
	close(certChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.error != nil {
			return result.error
		}
	}

	return nil
}

func (cv *CertificateValidator) validateSingleCertificate(certData []byte) error {
	return nil
}

func (cv *CertificateValidator) ValidateKeyPairsParallel(keyPairs []struct {
	Private interface{}
	Public  interface{}
}) error {
	if len(keyPairs) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(keyPairs))*5*time.Second)
	defer cancel()

	numWorkers := cv.maxWorkers
	if numWorkers > len(keyPairs) {
		numWorkers = len(keyPairs)
	}

	taskChan := make(chan struct {
		pair  struct {
			Private interface{}
			Public  interface{}
		}
		index int
	}, len(keyPairs))
	
	resultChan := make(chan validationResult, len(keyPairs))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- validationResult{index: task.index, error: ctx.Err()}
					return
				default:
				}
				
				if err := pq.ValidateKeyPair(task.pair.Private, task.pair.Public); err != nil {
					resultChan <- validationResult{index: task.index, error: fmt.Errorf("key pair %d validation failed: %w", task.index, err)}
					continue
				}
				
				resultChan <- validationResult{index: task.index, error: nil}
			}
		}()
	}

	for i, kp := range keyPairs {
		taskChan <- struct {
			pair  struct {
				Private interface{}
				Public  interface{}
			}
			index int
		}{pair: kp, index: i}
	}
	close(taskChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.error != nil {
			return result.error
		}
	}

	return nil
}

func (cv *CertificateValidator) ValidateAlgorithmStrengthsParallel(algorithms []string) error {
	if len(algorithms) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resultChan := make(chan validationResult, len(algorithms))
	var wg sync.WaitGroup

	for i, algorithm := range algorithms {
		wg.Add(1)
		go func(index int, alg string) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				resultChan <- validationResult{index: index, error: ctx.Err()}
				return
			default:
			}
			
			if err := cv.ValidateSignatureStrength(alg); err != nil {
				resultChan <- validationResult{index: index, error: fmt.Errorf("algorithm %s strength validation failed: %w", alg, err)}
				return
			}
			
			resultChan <- validationResult{index: index, error: nil}
		}(i, algorithm)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.error != nil {
			return result.error
		}
	}

	return nil
}