package ca

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type Issuer struct {
	config         *utils.Config
	rootCA         *RootCA
	intermediateCA *IntermediateCA
	validator      *CertificateValidator
	domainValidator *DomainValidator
	mu             sync.RWMutex
	workerPool     *WorkerPool
}

type WorkerPool struct {
	workers    int
	maxWorkers int
}

func NewWorkerPool() *WorkerPool {
	maxWorkers := runtime.NumCPU() * 2
	if maxWorkers > 20 {
		maxWorkers = 20
	}
	return &WorkerPool{
		workers:    maxWorkers / 2,
		maxWorkers: maxWorkers,
	}
}

type CertificateRequest struct {
	CommonName       string
	SubjectAltNames  []string
	ValidityDays     int
	Customer         *storage.Customer
	Algorithm        string
	TemplateID       int
	KeyUsage         x509.KeyUsage
	ExtKeyUsage      []x509.ExtKeyUsage
	Subject          pkix.Name
	DNSNames         []string
	IPAddresses      []net.IP
	EmailAddresses   []string
	URIs             []string
	CRLDistPoints    []string
	OCSPServer       []string
	IsCA             bool
	MaxPathLen       int
	UseMultiPQC      bool
	KEMAlgorithm     string
}

type CertificateResponse struct {
	SerialNumber         string
	CertificatePEM       string
	PrivateKeyPEM        string
	MultiPQCCertificates []string
	MultiPQCPrivateKeys  []string
	KEMCertificatePEM    string
	KEMPrivateKeyPEM     string
	KEMPublicKeyPEM      string
	Algorithms           []string
	NotBefore            time.Time
	NotAfter             time.Time
	Fingerprint          string
	KeyID                string
	IsMultiPQC           bool
	HasKEM               bool
}

type BatchCertificateRequest struct {
	Requests []CertificateRequest
	BatchID  string
	Timeout  time.Duration
}

type BatchCertificateResponse struct {
	Responses []CertificateResponse
	Errors    []error
	BatchID   string
	Timing    map[string]time.Duration
	Succeeded int
	Failed    int
}

type RevocationRequest struct {
	SerialNumbers []string
	Reason        int
	RevocationTime time.Time
}

type RevocationResponse struct {
	Results map[string]bool
	Errors  map[string]error
}

type IntermediateCARequest struct {
	CommonName   string
	Country      string
	State        string
	City         string
	Org          string
	OrgUnit      string
	Customer     *storage.Customer
	Algorithm    string
	ValidityDays int
	KeyUsage     x509.KeyUsage
	MaxPathLen   int
	UseMultiPQC  bool
	KEMAlgorithm string
}

type MultiPQCKeyPair struct {
	PrivateKey interface{}
	PublicKey  interface{}
	KEMPrivate interface{}
	KEMPublic  interface{}
}

type PQPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	PublicKey  asn1.BitString
	Parameters asn1.RawValue `asn1:"optional"`
}

type certificateTask struct {
	request *CertificateRequest
	index   int
}

type certificateResult struct {
	response *CertificateResponse
	error    error
	index    int
	timing   time.Duration
}

type certValidationTask struct {
	certPEM string
	index   int
}

type certValidationResult struct {
	cert  *x509.Certificate
	index int
	error error
}

type revocationTask struct {
	serialNumber string
	index        int
}

type revocationResult struct {
	serialNumber string
	isRevoked    bool
	error        error
	index        int
}

type signatureTask struct {
	data      []byte
	publicKey interface{}
	signature []byte
	index     int
}

type signatureResult struct {
	valid bool
	error error
	index int
}

func NewIssuer(config *utils.Config) *Issuer {
	rootCA := NewRootCA(config)
	intermediateCA := NewIntermediateCA(config, rootCA)
	validator := NewCertificateValidator(config, utils.NewLogger("info"))
	domainValidator := NewDomainValidator()
	
	rootCA.Initialize()
	intermediateCA.Initialize()

	return &Issuer{
		config:          config,
		rootCA:          rootCA,
		intermediateCA:  intermediateCA,
		validator:       validator,
		domainValidator: domainValidator,
		workerPool:      NewWorkerPool(),
	}
}

func (ei *Issuer) IssueCertificatesBatch(batchReq *BatchCertificateRequest) (*BatchCertificateResponse, error) {
	if len(batchReq.Requests) == 0 {
		return &BatchCertificateResponse{
			BatchID:   batchReq.BatchID,
			Responses: []CertificateResponse{},
			Errors:    []error{},
		}, nil
	}

	timeout := batchReq.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	numWorkers := ei.calculateWorkers(len(batchReq.Requests))
	taskChan := make(chan certificateTask, len(batchReq.Requests))
	resultChan := make(chan certificateResult, len(batchReq.Requests))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- certificateResult{
						index: task.index,
						error: ctx.Err(),
					}
					return
				default:
				}
				
				start := time.Now()
				response, err := ei.IssueCertificate(task.request)
				duration := time.Since(start)
				
				resultChan <- certificateResult{
					response: response,
					error:    err,
					index:    task.index,
					timing:   duration,
				}
			}
		}(i)
	}

	for i, req := range batchReq.Requests {
		taskChan <- certificateTask{request: &req, index: i}
	}
	close(taskChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	responses := make([]CertificateResponse, len(batchReq.Requests))
	errors := make([]error, len(batchReq.Requests))
	timing := make(map[string]time.Duration)
	succeeded := 0
	failed := 0

	for result := range resultChan {
		if result.response != nil {
			responses[result.index] = *result.response
			succeeded++
		} else {
			failed++
		}
		errors[result.index] = result.error
		timing[fmt.Sprintf("cert_%d", result.index)] = result.timing
	}

	return &BatchCertificateResponse{
		Responses: responses,
		Errors:    errors,
		BatchID:   batchReq.BatchID,
		Timing:    timing,
		Succeeded: succeeded,
		Failed:    failed,
	}, nil
}

func (ei *Issuer) ValidateCertificateChainParallel(chainPEM []string) error {
	if len(chainPEM) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskChan := make(chan certValidationTask, len(chainPEM))
	resultChan := make(chan certValidationResult, len(chainPEM))
	var wg sync.WaitGroup

	numWorkers := ei.calculateWorkers(len(chainPEM))
	if numWorkers > 5 {
		numWorkers = 5
	}
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- certValidationResult{
						index: task.index,
						error: ctx.Err(),
					}
					return
				default:
				}
				
				block, _ := pem.Decode([]byte(task.certPEM))
				if block == nil {
					resultChan <- certValidationResult{
						index: task.index,
						error: fmt.Errorf("failed to decode PEM at index %d", task.index),
					}
					continue
				}
				
				cert, err := x509.ParseCertificate(block.Bytes)
				resultChan <- certValidationResult{
					cert:  cert,
					index: task.index,
					error: err,
				}
			}
		}()
	}

	for i, certPEM := range chainPEM {
		taskChan <- certValidationTask{
			certPEM: certPEM,
			index:   i,
		}
	}
	close(taskChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	certs := make([]*x509.Certificate, len(chainPEM))
	for result := range resultChan {
		if result.error != nil {
			return fmt.Errorf("parsing error at index %d: %w", result.index, result.error)
		}
		certs[result.index] = result.cert
	}

	return ei.validateChainRelationshipsParallel(ctx, certs)
}

func (ei *Issuer) validateChainRelationshipsParallel(ctx context.Context, certs []*x509.Certificate) error {
	if len(certs) < 2 {
		return nil
	}

	type chainValidation struct {
		childIndex  int
		parentIndex int
	}

	type chainResult struct {
		error error
		pair  string
	}

	validationChan := make(chan chainValidation, len(certs)-1)
	resultChan := make(chan chainResult, len(certs)-1)
	var wg sync.WaitGroup

	numWorkers := len(certs) - 1
	if numWorkers > 3 {
		numWorkers = 3
	}
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for validation := range validationChan {
				select {
				case <-ctx.Done():
					resultChan <- chainResult{
						error: ctx.Err(),
						pair:  fmt.Sprintf("%d->%d", validation.childIndex, validation.parentIndex),
					}
					return
				default:
				}
				
				child := certs[validation.childIndex]
				parent := certs[validation.parentIndex]
				
				err := child.CheckSignatureFrom(parent)
				resultChan <- chainResult{
					error: err,
					pair:  fmt.Sprintf("%d->%d", validation.childIndex, validation.parentIndex),
				}
			}
		}()
	}

	for i := 0; i < len(certs)-1; i++ {
		validationChan <- chainValidation{
			childIndex:  i,
			parentIndex: i + 1,
		}
	}
	close(validationChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.error != nil {
			return fmt.Errorf("chain validation failed for %s: %w", result.pair, result.error)
		}
	}

	return nil
}

func (ei *Issuer) CheckRevocationStatusParallel(serialNumbers []string) (*RevocationResponse, error) {
	if len(serialNumbers) == 0 {
		return &RevocationResponse{
			Results: make(map[string]bool),
			Errors:  make(map[string]error),
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskChan := make(chan revocationTask, len(serialNumbers))
	resultChan := make(chan revocationResult, len(serialNumbers))
	var wg sync.WaitGroup

	numWorkers := ei.calculateWorkers(len(serialNumbers))
	if numWorkers > 15 {
		numWorkers = 15
	}
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- revocationResult{
						serialNumber: task.serialNumber,
						index:        task.index,
						error:        ctx.Err(),
					}
					return
				default:
				}
				
				isRevoked, err := ei.checkSingleRevocationStatus(task.serialNumber)
				resultChan <- revocationResult{
					serialNumber: task.serialNumber,
					isRevoked:    isRevoked,
					error:        err,
					index:        task.index,
				}
			}
		}()
	}

	for i, serialNumber := range serialNumbers {
		taskChan <- revocationTask{serialNumber: serialNumber, index: i}
	}
	close(taskChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	results := make(map[string]bool)
	errors := make(map[string]error)

	for result := range resultChan {
		results[result.serialNumber] = result.isRevoked
		if result.error != nil {
			errors[result.serialNumber] = result.error
		}
	}

	return &RevocationResponse{
		Results: results,
		Errors:  errors,
	}, nil
}

func (ei *Issuer) VerifySignaturesBatch(data [][]byte, publicKeys []interface{}, signatures [][]byte) ([]bool, error) {
	if len(data) != len(publicKeys) || len(data) != len(signatures) {
		return nil, fmt.Errorf("mismatched array lengths")
	}

	if len(data) == 0 {
		return []bool{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	taskChan := make(chan signatureTask, len(data))
	resultChan := make(chan signatureResult, len(data))
	var wg sync.WaitGroup

	numWorkers := ei.calculateWorkers(len(data))
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- signatureResult{
						index: task.index,
						error: ctx.Err(),
					}
					return
				default:
				}
				
				valid := pq.Verify(task.publicKey, task.data, task.signature)
				resultChan <- signatureResult{
					valid: valid,
					index: task.index,
				}
			}
		}()
	}

	for i := 0; i < len(data); i++ {
		taskChan <- signatureTask{
			data:      data[i],
			publicKey: publicKeys[i],
			signature: signatures[i],
			index:     i,
		}
	}
	close(taskChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	results := make([]bool, len(data))
	for result := range resultChan {
		if result.error != nil {
			return nil, fmt.Errorf("verification failed at index %d: %w", result.index, result.error)
		}
		results[result.index] = result.valid
	}

	return results, nil
}

func (ei *Issuer) GenerateKeysBatch(algorithms []string, count int) ([]interface{}, []interface{}, error) {
	if count <= 0 || len(algorithms) == 0 {
		return nil, nil, fmt.Errorf("invalid parameters")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	type keyGenTask struct {
		algorithm string
		index     int
	}

	type keyGenResult struct {
		privateKey interface{}
		publicKey  interface{}
		error      error
		index      int
	}

	totalKeys := len(algorithms) * count
	taskChan := make(chan keyGenTask, totalKeys)
	resultChan := make(chan keyGenResult, totalKeys)
	var wg sync.WaitGroup

	numWorkers := ei.calculateWorkers(totalKeys)
	if numWorkers > 10 {
		numWorkers = 10
	}
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for task := range taskChan {
				select {
				case <-ctx.Done():
					resultChan <- keyGenResult{
						index: task.index,
						error: ctx.Err(),
					}
					return
				default:
				}
				
				privateKey, err := pq.GenerateKey(task.algorithm)
				if err != nil {
					resultChan <- keyGenResult{
						index: task.index,
						error: err,
					}
					continue
				}
				
				publicKey, err := pq.GetPublicKey(privateKey)
				resultChan <- keyGenResult{
					privateKey: privateKey,
					publicKey:  publicKey,
					error:      err,
					index:      task.index,
				}
			}
		}()
	}

	taskIndex := 0
	for _, algorithm := range algorithms {
		for i := 0; i < count; i++ {
			taskChan <- keyGenTask{
				algorithm: algorithm,
				index:     taskIndex,
			}
			taskIndex++
		}
	}
	close(taskChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	privateKeys := make([]interface{}, totalKeys)
	publicKeys := make([]interface{}, totalKeys)

	for result := range resultChan {
		if result.error != nil {
			return nil, nil, fmt.Errorf("key generation failed at index %d: %w", result.index, result.error)
		}
		privateKeys[result.index] = result.privateKey
		publicKeys[result.index] = result.publicKey
	}

	return privateKeys, publicKeys, nil
}

func (ei *Issuer) calculateWorkers(taskCount int) int {
	if taskCount <= 0 {
		return 1
	}
	
	workers := ei.workerPool.workers
	if taskCount < workers {
		workers = taskCount
	}
	
	if workers > ei.workerPool.maxWorkers {
		workers = ei.workerPool.maxWorkers
	}
	
	return workers
}

func (ei *Issuer) checkSingleRevocationStatus(serialNumber string) (bool, error) {
	return false, nil
}

func (ei *Issuer) IssueCertificate(req *CertificateRequest) (*CertificateResponse, error) {
	if err := ei.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid certificate request: %w", err)
	}

	if err := ei.validateDomainOwnershipSecure(req); err != nil {
		return nil, fmt.Errorf("domain validation failed: %w", err)
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "dilithium3"
	}

	var response *CertificateResponse
	var err error

	if req.UseMultiPQC {
		response, err = ei.issueMultiPQCCertificate(req)
	} else {
		response, err = ei.issuePQCertificate(req, algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	if err := ei.validateIssuedCertificate(response); err != nil {
		return nil, fmt.Errorf("issued certificate failed validation: %w", err)
	}

	return response, nil
}

func (ei *Issuer) validateDomainOwnershipSecure(req *CertificateRequest) error {
	domains := []string{req.CommonName}
	domains = append(domains, req.SubjectAltNames...)

	for _, domain := range domains {
		if strings.TrimSpace(domain) == "" {
			continue
		}

		domain = strings.TrimSpace(domain)
		
		if err := ei.domainValidator.ValidateSingleSAN(domain); err != nil {
			return fmt.Errorf("domain format validation failed for %s: %w", domain, err)
		}

		token, err := ei.domainValidator.GenerateValidationToken()
		if err != nil {
			return fmt.Errorf("failed to generate validation token for %s: %w", domain, err)
		}

		var result *ValidationResult
		if strings.HasPrefix(domain, "*.") {
			result, err = ei.domainValidator.ValidateWildcardDomainActual(domain, token)
		} else {
			result, err = ei.domainValidator.ValidateDomainControlActual(domain, token)
		}

		if err != nil {
			return fmt.Errorf("domain validation error for %s: %w", domain, err)
		}

		if !result.Valid {
			return fmt.Errorf("domain validation failed for %s: %s", domain, result.Details)
		}
	}

	return nil
}

func (ei *Issuer) validateIssuedCertificate(response *CertificateResponse) error {
	if response == nil {
		return fmt.Errorf("certificate response is nil")
	}

	block, _ := pem.Decode([]byte(response.CertificatePEM))
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	if err := ei.validateCertificateChainComplete(cert); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("issued certificate is already expired")
	}

	if cert.NotBefore.After(cert.NotAfter) {
		return fmt.Errorf("certificate validity period is invalid")
	}

	if response.IsMultiPQC && len(response.MultiPQCCertificates) == 0 {
		return fmt.Errorf("multi-PQC certificate missing PQC components")
	}

	if response.HasKEM && response.KEMPublicKeyPEM == "" {
		return fmt.Errorf("KEM certificate missing KEM public key")
	}

	return nil
}

func (ei *Issuer) validateCertificateChainComplete(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	intermediateCert := ei.intermediateCA.GetCertificate()
	if intermediateCert == nil {
		return fmt.Errorf("intermediate CA certificate not available")
	}

	rootCert := ei.rootCA.GetCertificate()
	if rootCert == nil {
		return fmt.Errorf("root CA certificate not available")
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	for _, chain := range chains {
		if len(chain) < 2 {
			return fmt.Errorf("invalid chain length: %d", len(chain))
		}

		for i := 0; i < len(chain)-1; i++ {
			child := chain[i]
			parent := chain[i+1]
			
			if err := child.CheckSignatureFrom(parent); err != nil {
				return fmt.Errorf("signature verification failed at level %d: %w", i, err)
			}

			if !child.NotBefore.Before(child.NotAfter) {
				return fmt.Errorf("invalid validity period at level %d", i)
			}

			if child.NotAfter.After(parent.NotAfter) {
				return fmt.Errorf("child certificate expires after parent at level %d", i)
			}
		}
	}

	return nil
}

func (ei *Issuer) issuePQCertificate(req *CertificateRequest, algorithm string) (*CertificateResponse, error) {
	var privateKey interface{}
	var publicKey interface{}
	var err error

	if req.UseMultiPQC {
		multiPQCKey, err := pq.GenerateMultiPQCKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate multi-PQC key: %w", err)
		}
		privateKey = multiPQCKey
		publicKey, err = multiPQCKey.GetPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get multi-PQC public key: %w", err)
		}
	} else {
		privateKey, err = pq.GenerateKey(algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PQ key: %w", err)
		}
		publicKey, err = pq.GetPublicKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}
	}

	serialNumber, err := ei.generateSecureSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	subject := ei.buildSubject(req)
	template := ei.buildCertificateTemplate(req, subject, serialNumber)

	certDER, err := ei.intermediateCA.SignCertificate(template, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	var privateKeyDER []byte
	var keyPEM []byte

	if req.UseMultiPQC {
		privateKeyDER, err = pq.MarshalMultiPQCPrivateKey(privateKey.(*pq.MultiPQCPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal multi-PQC private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "MULTI-PQC PRIVATE KEY",
			Bytes: privateKeyDER,
		})
	} else {
		privateKeyDER, err = pq.MarshalPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyDER,
		})
	}

	fingerprint, err := calculateFingerprint(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate fingerprint: %w", err)
	}

	keyID, err := ei.calculatePQKeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate key ID: %w", err)
	}

	var algorithms []string
	if req.UseMultiPQC {
		multiKey := privateKey.(*pq.MultiPQCPrivateKey)
		algorithms = []string{
			"multi-pqc",
			multiKey.PrimaryAlgorithm,
			multiKey.SecondaryAlgorithm,
			multiKey.TertiaryAlgorithm,
		}
	} else {
		algorithms = []string{algorithm}
	}

	response := &CertificateResponse{
		SerialNumber:   serialNumber.String(),
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		Algorithms:     algorithms,
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
		Fingerprint:    fingerprint,
		KeyID:          keyID,
		IsMultiPQC:     req.UseMultiPQC,
		HasKEM:         false,
	}

	if req.UseMultiPQC {
		response.MultiPQCCertificates = []string{string(certPEM)}
		response.MultiPQCPrivateKeys = []string{string(keyPEM)}
	}

	if req.KEMAlgorithm != "" && pq.IsKEMAlgorithm(req.KEMAlgorithm) {
		kemKeys, err := ei.generateKEMKeyPair(req.KEMAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate KEM keys: %w", err)
		}

		kemPublicPEM, err := ei.marshalKEMPublicKey(kemKeys.KEMPublic, req.KEMAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal KEM public key: %w", err)
		}

		kemPrivatePEM, err := ei.marshalKEMPrivateKey(kemKeys.KEMPrivate, req.KEMAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal KEM private key: %w", err)
		}

		response.KEMPublicKeyPEM = string(kemPublicPEM)
		response.KEMPrivateKeyPEM = string(kemPrivatePEM)
		response.HasKEM = true
		response.Algorithms = append(response.Algorithms, req.KEMAlgorithm)
	}

	return response, nil
}

func (ei *Issuer) issueMultiPQCCertificate(req *CertificateRequest) (*CertificateResponse, error) {
	req.UseMultiPQC = true
	return ei.issuePQCertificate(req, "multi-pqc")
}

func (ei *Issuer) validateRequest(req *CertificateRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.CommonName == "" {
		return fmt.Errorf("common name is required")
	}

	if len(req.CommonName) > 64 {
		return fmt.Errorf("common name too long")
	}

	if req.ValidityDays < 1 || req.ValidityDays > 3650 {
		return fmt.Errorf("invalid validity days: %d", req.ValidityDays)
	}

	if req.Algorithm != "" && !ei.isValidAlgorithm(req.Algorithm) {
		return fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
	}

	if req.KEMAlgorithm != "" && !pq.IsKEMAlgorithm(req.KEMAlgorithm) {
		return fmt.Errorf("unsupported KEM algorithm: %s", req.KEMAlgorithm)
	}

	for _, san := range req.SubjectAltNames {
		if err := ei.validateSAN(san); err != nil {
			return fmt.Errorf("invalid SAN '%s': %w", san, err)
		}
	}

	return nil
}

func (ei *Issuer) validateIntermediateRequest(req *IntermediateCARequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.CommonName == "" {
		return fmt.Errorf("common name is required")
	}

	if req.Country == "" || req.State == "" || req.City == "" || req.Org == "" {
		return fmt.Errorf("all subject fields are required for intermediate CA")
	}

	if req.ValidityDays < 365 || req.ValidityDays > 7300 {
		return fmt.Errorf("invalid validity days for intermediate CA: %d", req.ValidityDays)
	}

	if req.Algorithm != "" && !ei.isValidAlgorithm(req.Algorithm) {
		return fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
	}

	if req.KEMAlgorithm != "" && !pq.IsKEMAlgorithm(req.KEMAlgorithm) {
		return fmt.Errorf("unsupported KEM algorithm: %s", req.KEMAlgorithm)
	}

	return nil
}

func (ei *Issuer) isValidAlgorithm(algorithm string) bool {
	validAlgorithms := []string{
		"dilithium2", "dilithium3", "dilithium5",
		"sphincs-sha256-128f", "sphincs-sha256-128s",
		"sphincs-sha256-192f", "sphincs-sha256-256f",
		"kyber512", "kyber768", "kyber1024",
		"multi-pqc",
	}

	for _, alg := range validAlgorithms {
		if algorithm == alg {
			return true
		}
	}
	return false
}

func (ei *Issuer) validateSAN(san string) error {
	san = strings.TrimSpace(san)
	if len(san) == 0 {
		return fmt.Errorf("empty SAN")
	}

	if net.ParseIP(san) != nil {
		return nil
	}

	if strings.Contains(san, "@") {
		return nil
	}

	if strings.HasPrefix(san, "*.") {
		baseDomain := san[2:]
		if strings.Contains(baseDomain, "*") {
			return fmt.Errorf("multiple wildcards not allowed")
		}
		return ei.validateDomainName(baseDomain)
	}

	return ei.validateDomainName(san)
}

func (ei *Issuer) validateDomainName(domain string) error {
	if len(domain) > 253 {
		return fmt.Errorf("domain name too long")
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid label length")
		}
	}

	return nil
}

func (ei *Issuer) buildSubject(req *CertificateRequest) pkix.Name {
	if req.Subject.CommonName != "" {
		return req.Subject
	}

	subject := pkix.Name{
		CommonName: req.CommonName,
	}

	if req.Customer != nil {
		subject.Organization = []string{req.Customer.CompanyName}
		subject.OrganizationalUnit = []string{"QuantumCA Certificate"}
		subject.Country = []string{"US"}
	}

	return subject
}

func (ei *Issuer) buildCertificateTemplate(req *CertificateRequest, subject pkix.Name, serialNumber *big.Int) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, req.ValidityDays),
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
	}

	if req.IsCA {
		template.MaxPathLen = req.MaxPathLen
		template.MaxPathLenZero = req.MaxPathLen == 0
	}

	ei.addSubjectAlternativeNames(template, req)
	ei.addStandardExtensions(template)

	if req.IsCA {
		ei.addCAExtensions(template)
	} else {
		ei.addEndEntityExtensions(template)
	}

	return template
}

func (ei *Issuer) addSubjectAlternativeNames(template *x509.Certificate, req *CertificateRequest) {
	for _, san := range req.SubjectAltNames {
		san = strings.TrimSpace(san)
		if len(san) == 0 {
			continue
		}

		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if strings.Contains(san, "@") {
			template.EmailAddresses = append(template.EmailAddresses, san)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	template.DNSNames = append(template.DNSNames, req.DNSNames...)
	template.IPAddresses = append(template.IPAddresses, req.IPAddresses...)
	template.EmailAddresses = append(template.EmailAddresses, req.EmailAddresses...)
}

func (ei *Issuer) addStandardExtensions(template *x509.Certificate) {
	template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)

	if len(template.CRLDistributionPoints) == 0 {
		template.CRLDistributionPoints = []string{
			fmt.Sprintf("http://crl.%s/quantumca.crl", ei.config.Environment),
		}
	}

	if len(template.OCSPServer) == 0 {
		template.OCSPServer = []string{
			fmt.Sprintf("http://ocsp.%s", ei.config.Environment),
		}
	}

	template.IssuingCertificateURL = []string{
		fmt.Sprintf("http://certs.%s/ca.crt", ei.config.Environment),
	}
}

func (ei *Issuer) addCAExtensions(template *x509.Certificate) {
	if template.KeyUsage == 0 {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	}
}

func (ei *Issuer) addEndEntityExtensions(template *x509.Certificate) {
	if template.KeyUsage == 0 {
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	}
}

func calculateFingerprint(certDER []byte) (string, error) {
	hash := sha256.Sum256(certDER)
	return fmt.Sprintf("%x", hash), nil
}

func (ei *Issuer) generateSecureSerialNumber() (*big.Int, error) {
	ei.mu.Lock()
	defer ei.mu.Unlock()
	
	serialBytes := make([]byte, 20)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random serial number: %w", err)
	}
	
	serialBytes[0] &= 0x7F
	
	serial := new(big.Int).SetBytes(serialBytes)
	
	if serial.Sign() <= 0 {
		return nil, fmt.Errorf("invalid serial number generated")
	}
	
	return serial, nil
}

func (ei *Issuer) generateKEMKeyPair(kemAlgorithm string) (*MultiPQCKeyPair, error) {
	if !pq.IsKEMAlgorithm(kemAlgorithm) {
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", kemAlgorithm)
	}

	kemPrivate, err := pq.GenerateKey(kemAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM private key: %w", err)
	}

	kemPublic, err := pq.GetPublicKey(kemPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEM public key: %w", err)
	}

	return &MultiPQCKeyPair{
		KEMPrivate: kemPrivate,
		KEMPublic:  kemPublic,
	}, nil
}

func (ei *Issuer) marshalKEMPublicKey(kemPublic interface{}, algorithm string) ([]byte, error) {
	pubKeyBytes, err := pq.MarshalPublicKey(kemPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KEM public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "KEM PUBLIC KEY",
		Bytes: pubKeyBytes,
		Headers: map[string]string{
			"Algorithm": algorithm,
		},
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func (ei *Issuer) marshalKEMPrivateKey(kemPrivate interface{}, algorithm string) ([]byte, error) {
	privKeyBytes, err := pq.MarshalPrivateKey(kemPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KEM private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "KEM PRIVATE KEY",
		Bytes: privKeyBytes,
		Headers: map[string]string{
			"Algorithm": algorithm,
		},
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func (ei *Issuer) calculatePQKeyID(publicKey interface{}) (string, error) {
	var pubKeyBytes []byte
	var err error

	switch key := publicKey.(type) {
	case *pq.MultiPQCPublicKey:
		pubKeyBytes, err = pq.MarshalMultiPQCPublicKey(key)
	default:
		pubKeyBytes, err = pq.MarshalPublicKey(publicKey)
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
	return fmt.Sprintf("%x", hash[:8]), nil
}

func (ei *Issuer) IssueIntermediateCA(req *IntermediateCARequest) (*CertificateResponse, error) {
	if err := ei.validateIntermediateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid intermediate CA request: %w", err)
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "dilithium5"
	}

	var response *CertificateResponse
	var err error

	if req.UseMultiPQC {
		response, err = ei.issueMultiPQCIntermediateCA(req)
	} else {
		response, err = ei.issuePQIntermediateCA(req, algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to issue intermediate CA: %w", err)
	}

	if err := ei.validateIssuedCertificate(response); err != nil {
		return nil, fmt.Errorf("issued intermediate CA failed validation: %w", err)
	}

	return response, nil
}

func (ei *Issuer) issueMultiPQCIntermediateCA(req *IntermediateCARequest) (*CertificateResponse, error) {
	multiPQCKey, err := pq.GenerateMultiPQCKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate multi-PQC key: %w", err)
	}

	multiPQCPublic, err := multiPQCKey.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get multi-PQC public key: %w", err)
	}

	serialNumber, err := ei.generateSecureSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	subject := pkix.Name{
		CommonName:         req.CommonName,
		Country:            []string{req.Country},
		Province:           []string{req.State},
		Locality:           []string{req.City},
		Organization:       []string{req.Org},
		OrganizationalUnit: []string{req.OrgUnit},
	}

	validityDays := req.ValidityDays
	if validityDays == 0 {
		validityDays = ei.config.IntermediateCAValidityDays
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              req.KeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            req.MaxPathLen,
		MaxPathLenZero:        req.MaxPathLen == 0,
	}

	ei.addStandardExtensions(template)
	ei.addCAExtensions(template)

	certDER, err := ei.rootCA.SignCertificate(template, multiPQCPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to sign intermediate CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	multiPQCPrivateKeyDER, err := pq.MarshalMultiPQCPrivateKey(multiPQCKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal multi-PQC private key: %w", err)
	}

	multiPQCKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "MULTI-PQC PRIVATE KEY",
		Bytes: multiPQCPrivateKeyDER,
	})

	fingerprint, err := calculateFingerprint(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate fingerprint: %w", err)
   }

   keyID := fmt.Sprintf("%x", multiPQCKey.CombinedKeyID[:8])

   algorithms := []string{
   	"multi-pqc",
   	multiPQCKey.PrimaryAlgorithm,
   	multiPQCKey.SecondaryAlgorithm,
   	multiPQCKey.TertiaryAlgorithm,
   }

   response := &CertificateResponse{
   	SerialNumber:    serialNumber.String(),
   	CertificatePEM:  string(certPEM),
   	PrivateKeyPEM:   string(multiPQCKeyPEM),
   	MultiPQCCertificates: []string{
   		string(certPEM),
   	},
   	MultiPQCPrivateKeys: []string{
   		string(multiPQCKeyPEM),
   	},
   	Algorithms:  algorithms,
   	NotBefore:   template.NotBefore,
   	NotAfter:    template.NotAfter,
   	Fingerprint: fingerprint,
   	KeyID:       keyID,
   	IsMultiPQC:  true,
   	HasKEM:      false,
   }

   if req.KEMAlgorithm != "" && pq.IsKEMAlgorithm(req.KEMAlgorithm) {
   	kemKeys, err := ei.generateKEMKeyPair(req.KEMAlgorithm)
   	if err != nil {
   		return nil, fmt.Errorf("failed to generate KEM keys: %w", err)
   	}

   	kemPublicPEM, err := ei.marshalKEMPublicKey(kemKeys.KEMPublic, req.KEMAlgorithm)
   	if err != nil {
   		return nil, fmt.Errorf("failed to marshal KEM public key: %w", err)
   	}

   	kemPrivatePEM, err := ei.marshalKEMPrivateKey(kemKeys.KEMPrivate, req.KEMAlgorithm)
   	if err != nil {
   		return nil, fmt.Errorf("failed to marshal KEM private key: %w", err)
   	}

   	response.KEMPublicKeyPEM = string(kemPublicPEM)
   	response.KEMPrivateKeyPEM = string(kemPrivatePEM)
   	response.HasKEM = true
   	response.Algorithms = append(response.Algorithms, req.KEMAlgorithm)
   }

   return response, nil
}

func (ei *Issuer) issuePQIntermediateCA(req *IntermediateCARequest, algorithm string) (*CertificateResponse, error) {
   privateKey, err := pq.GenerateKey(algorithm)
   if err != nil {
   	return nil, fmt.Errorf("failed to generate intermediate CA key: %w", err)
   }

   publicKey, err := pq.GetPublicKey(privateKey)
   if err != nil {
   	return nil, fmt.Errorf("failed to get public key: %w", err)
   }

   serialNumber, err := ei.generateSecureSerialNumber()
   if err != nil {
   	return nil, fmt.Errorf("failed to generate serial number: %w", err)
   }

   subject := pkix.Name{
   	CommonName:         req.CommonName,
   	Country:            []string{req.Country},
   	Province:           []string{req.State},
   	Locality:           []string{req.City},
   	Organization:       []string{req.Org},
   	OrganizationalUnit: []string{req.OrgUnit},
   }

   validityDays := req.ValidityDays
   if validityDays == 0 {
   	validityDays = ei.config.IntermediateCAValidityDays
   }

   template := &x509.Certificate{
   	SerialNumber:          serialNumber,
   	Subject:               subject,
   	NotBefore:             time.Now(),
   	NotAfter:              time.Now().AddDate(0, 0, validityDays),
   	KeyUsage:              req.KeyUsage,
   	BasicConstraintsValid: true,
   	IsCA:                  true,
   	MaxPathLen:            req.MaxPathLen,
   	MaxPathLenZero:        req.MaxPathLen == 0,
   }

   ei.addStandardExtensions(template)
   ei.addCAExtensions(template)

   certDER, err := ei.rootCA.SignCertificate(template, publicKey)
   if err != nil {
   	return nil, fmt.Errorf("failed to sign intermediate CA certificate: %w", err)
   }

   certPEM := pem.EncodeToMemory(&pem.Block{
   	Type:  "CERTIFICATE",
   	Bytes: certDER,
   })

   privateKeyDER, err := pq.MarshalPrivateKey(privateKey)
   if err != nil {
   	return nil, fmt.Errorf("failed to marshal private key: %w", err)
   }

   keyPEM := pem.EncodeToMemory(&pem.Block{
   	Type:  "PRIVATE KEY",
   	Bytes: privateKeyDER,
   })

   fingerprint, err := calculateFingerprint(certDER)
   if err != nil {
   	return nil, fmt.Errorf("failed to calculate fingerprint: %w", err)
   }

   keyID, err := ei.calculatePQKeyID(publicKey)
   if err != nil {
   	return nil, fmt.Errorf("failed to calculate key ID: %w", err)
   }

   response := &CertificateResponse{
   	SerialNumber:   serialNumber.String(),
   	CertificatePEM: string(certPEM),
   	PrivateKeyPEM:  string(keyPEM),
   	Algorithms:     []string{algorithm},
   	NotBefore:      template.NotBefore,
   	NotAfter:       template.NotAfter,
   	Fingerprint:    fingerprint,
   	KeyID:          keyID,
   	IsMultiPQC:     false,
   	HasKEM:         false,
   }

   if req.KEMAlgorithm != "" && pq.IsKEMAlgorithm(req.KEMAlgorithm) {
   	kemKeys, err := ei.generateKEMKeyPair(req.KEMAlgorithm)
   	if err != nil {
   		return nil, fmt.Errorf("failed to generate KEM keys: %w", err)
   	}

   	kemPublicPEM, err := ei.marshalKEMPublicKey(kemKeys.KEMPublic, req.KEMAlgorithm)
   	if err != nil {
   		return nil, fmt.Errorf("failed to marshal KEM public key: %w", err)
   	}

   	kemPrivatePEM, err := ei.marshalKEMPrivateKey(kemKeys.KEMPrivate, req.KEMAlgorithm)
   	if err != nil {
   		return nil, fmt.Errorf("failed to marshal KEM private key: %w", err)
   	}

   	response.KEMPublicKeyPEM = string(kemPublicPEM)
   	response.KEMPrivateKeyPEM = string(kemPrivatePEM)
   	response.HasKEM = true
   	response.Algorithms = append(response.Algorithms, req.KEMAlgorithm)
   }

   return response, nil
}