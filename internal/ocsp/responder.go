package ocsp

import (
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"quantumca-platform/internal/crypto/keymanager"
	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"

	"golang.org/x/crypto/ocsp"
)

type Responder struct {
	db           *sql.DB
	config       *utils.Config
	logger       *utils.Logger
	keyStore     *keymanager.EncryptedKeyStore
	issuerCert   *x509.Certificate
	issuerKey    interface{}
	pqIssuerKey  interface{}
	pqEnabled    bool
}

type CertificateStatus struct {
	Status       int
	SerialNumber *big.Int
	ThisUpdate   time.Time
	NextUpdate   time.Time
	RevokedAt    *time.Time
	Reason       int
}

type PQOCSPResponse struct {
	Status             int
	SerialNumber       *big.Int
	ThisUpdate         time.Time
	NextUpdate         time.Time
	RevokedAt          *time.Time
	RevocationReason   int
	PQSignature        []byte
	PQAlgorithm        string
	ClassicalSignature []byte
}

func NewResponder(db *sql.DB, config *utils.Config) *Responder {
	logger := utils.NewLogger(config.LogLevel)
	return &Responder{
		db:        db,
		config:    config,
		logger:    logger,
		pqEnabled: true,
	}
}

func (r *Responder) Initialize() error {
	keyStore, err := keymanager.NewEncryptedKeyStore(r.config.KeysPath, r.config.IntermediateCAPassphrase)
	if err != nil {
		return fmt.Errorf("failed to initialize key store: %w", err)
	}
	r.keyStore = keyStore

	if err := r.loadIssuerCredentials(); err != nil {
		return fmt.Errorf("failed to load issuer credentials: %w", err)
	}
	return nil
}

func (r *Responder) HandleRequest(requestBytes []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP request: %w", err)
	}

	if req.SerialNumber == nil {
		return nil, fmt.Errorf("missing serial number in OCSP request")
	}

	status, err := r.getCertificateStatus(req.SerialNumber)
	if err != nil {
		return r.createUnknownResponse(req)
	}

	cert, err := r.getCertificateBySerial(req.SerialNumber.String())
	if err != nil {
		return r.createStandardOCSPResponse(status, req)
	}

	if r.isPQCertificate(cert) {
		return r.createPQOCSPResponse(status, req, cert)
	}

	return r.createStandardOCSPResponse(status, req)
}

func (r *Responder) getCertificateBySerial(serialNumber string) (*storage.Certificate, error) {
	return storage.GetCertificateBySerial(r.db, serialNumber)
}

func (r *Responder) isPQCertificate(cert *storage.Certificate) bool {
	if cert == nil {
		return false
	}

	for _, algorithm := range cert.Algorithms {
		if r.isPQAlgorithm(algorithm) {
			return true
		}
	}
	return false
}

func (r *Responder) isPQAlgorithm(algorithm string) bool {
	pqAlgorithms := []string{
		"dilithium2", "dilithium3", "dilithium5",
		"falcon512", "falcon1024",
		"sphincs-sha256-128f", "sphincs-sha256-128s",
		"sphincs-sha256-192f", "sphincs-sha256-256f",
		"hybrid",
	}

	for _, alg := range pqAlgorithms {
		if algorithm == alg {
			return true
		}
	}
	return false
}

func (r *Responder) createPQOCSPResponse(status *CertificateStatus, req *ocsp.Request, cert *storage.Certificate) ([]byte, error) {
	if !r.pqEnabled || r.pqIssuerKey == nil {
		return r.createStandardOCSPResponse(status, req)
	}

	pqResponse := &PQOCSPResponse{
		Status:       status.Status,
		SerialNumber: status.SerialNumber,
		ThisUpdate:   status.ThisUpdate,
		NextUpdate:   status.NextUpdate,
	}

	if status.Status == ocsp.Revoked && status.RevokedAt != nil {
		pqResponse.RevokedAt = status.RevokedAt
		pqResponse.RevocationReason = status.Reason
	}

	responseData := r.marshalPQOCSPResponse(pqResponse)

	pqSignature, err := r.signWithPQKey(responseData)
	if err != nil {
		r.logger.LogError(err, "Failed to create PQ signature for OCSP response", map[string]interface{}{
			"serial": req.SerialNumber.String(),
		})
		return r.createStandardOCSPResponse(status, req)
	}

	pqResponse.PQSignature = pqSignature
	pqResponse.PQAlgorithm = r.getPQAlgorithmFromKey()

	classicalTemplate := ocsp.Response{
		Status:       status.Status,
		SerialNumber: status.SerialNumber,
		ThisUpdate:   status.ThisUpdate,
		NextUpdate:   status.NextUpdate,
	}

	if status.Status == ocsp.Revoked && status.RevokedAt != nil {
		classicalTemplate.RevokedAt = *status.RevokedAt
		classicalTemplate.RevocationReason = status.Reason
	}

	classicalResponse, err := r.createClassicalOCSPResponse(&classicalTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to create classical OCSP response: %w", err)
	}

	pqResponse.ClassicalSignature = classicalResponse

	return r.marshalHybridOCSPResponse(pqResponse), nil
}

func (r *Responder) createStandardOCSPResponse(status *CertificateStatus, req *ocsp.Request) ([]byte, error) {
	template := ocsp.Response{
		Status:       status.Status,
		SerialNumber: status.SerialNumber,
		ThisUpdate:   status.ThisUpdate,
		NextUpdate:   status.NextUpdate,
	}

	if status.Status == ocsp.Revoked && status.RevokedAt != nil {
		template.RevokedAt = *status.RevokedAt
		template.RevocationReason = status.Reason
	}

	return r.createClassicalOCSPResponse(&template)
}

func (r *Responder) signWithPQKey(data []byte) ([]byte, error) {
	if r.pqIssuerKey == nil {
		return nil, fmt.Errorf("PQ issuer key not available")
	}

	signature, err := pq.Sign(r.pqIssuerKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with PQ key: %w", err)
	}

	return signature, nil
}

func (r *Responder) getPQAlgorithmFromKey() string {
	if r.pqIssuerKey == nil {
		return "unknown"
	}

	switch r.pqIssuerKey.(type) {
	case *pq.DilithiumPrivateKey:
		if dilKey, ok := r.pqIssuerKey.(*pq.DilithiumPrivateKey); ok {
			return dilKey.Mode
		}
	case *pq.FalconPrivateKey:
		if falKey, ok := r.pqIssuerKey.(*pq.FalconPrivateKey); ok {
			return falKey.Mode
		}
	case *pq.SPHINCSPrivateKey:
		if sphKey, ok := r.pqIssuerKey.(*pq.SPHINCSPrivateKey); ok {
			return sphKey.Mode
		}
	}

	return "dilithium3"
}

func (r *Responder) marshalPQOCSPResponse(response *PQOCSPResponse) []byte {
	data := make([]byte, 0, 256)
	
	data = append(data, byte(response.Status))
	data = append(data, response.SerialNumber.Bytes()...)
	
	thisUpdateBytes, _ := response.ThisUpdate.MarshalBinary()
	data = append(data, thisUpdateBytes...)
	
	nextUpdateBytes, _ := response.NextUpdate.MarshalBinary()
	data = append(data, nextUpdateBytes...)
	
	if response.RevokedAt != nil {
		revokedBytes, _ := response.RevokedAt.MarshalBinary()
		data = append(data, revokedBytes...)
		data = append(data, byte(response.RevocationReason))
	}
	
	return data
}

func (r *Responder) marshalHybridOCSPResponse(response *PQOCSPResponse) []byte {
	data := make([]byte, 0, 1024)
	
	data = append(data, []byte("HYBRID-OCSP-v1")...)
	data = append(data, 0x00)
	
	algorithmBytes := []byte(response.PQAlgorithm)
	data = append(data, byte(len(algorithmBytes)))
	data = append(data, algorithmBytes...)
	
	pqSigLen := len(response.PQSignature)
	data = append(data, byte(pqSigLen>>8), byte(pqSigLen&0xFF))
	data = append(data, response.PQSignature...)
	
	classicalSigLen := len(response.ClassicalSignature)
	data = append(data, byte(classicalSigLen>>8), byte(classicalSigLen&0xFF))
	data = append(data, response.ClassicalSignature...)
	
	return data
}

func (r *Responder) getCertificateStatus(serialNumber *big.Int) (*CertificateStatus, error) {
	cert, err := storage.GetCertificateBySerial(r.db, serialNumber.String())
	if err != nil {
		return nil, err
	}

	status := &CertificateStatus{
		SerialNumber: serialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	switch cert.Status {
	case "active":
		if time.Now().After(cert.NotAfter) {
			status.Status = ocsp.Unknown
		} else {
			status.Status = ocsp.Good
		}
	case "revoked":
		status.Status = ocsp.Revoked
		if cert.RevokedAt != nil {
			status.RevokedAt = cert.RevokedAt
		} else {
			now := time.Now()
			status.RevokedAt = &now
		}
		status.Reason = r.mapRevocationReason(cert.RevocationReason)
	case "expired":
		status.Status = ocsp.Unknown
	default:
		status.Status = ocsp.Unknown
	}

	return status, nil
}

func (r *Responder) createUnknownResponse(req *ocsp.Request) ([]byte, error) {
	template := ocsp.Response{
		Status:       ocsp.Unknown,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	return r.createClassicalOCSPResponse(&template)
}

func (r *Responder) createClassicalOCSPResponse(template *ocsp.Response) ([]byte, error) {
	if r.issuerCert == nil || r.issuerKey == nil {
		if err := r.loadIssuerCredentials(); err != nil {
			return nil, fmt.Errorf("failed to load issuer credentials: %w", err)
		}
	}

	signer, ok := r.issuerKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("issuer key does not implement crypto.Signer")
	}

	return ocsp.CreateResponse(r.issuerCert, r.issuerCert, *template, signer)
}

func (r *Responder) loadIssuerCredentials() error {
	keyIDs, err := r.keyStore.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var intermediateKeyID, pqKeyID string
	for _, keyID := range keyIDs {
		metadata, err := r.keyStore.GetKeyMetadata(keyID)
		if err != nil {
			continue
		}
		if metadata.KeyType == "intermediate-ca" {
			if r.isPQAlgorithm(metadata.Algorithm) {
				pqKeyID = keyID
			} else {
				intermediateKeyID = keyID
			}
		}
	}

	if intermediateKeyID == "" && pqKeyID == "" {
		return fmt.Errorf("no intermediate CA keys found in key store")
	}

	if intermediateKeyID != "" {
		if err := r.loadClassicalIssuerKey(intermediateKeyID); err != nil {
			return fmt.Errorf("failed to load classical issuer key: %w", err)
		}
	}

	if pqKeyID != "" {
		if err := r.loadPQIssuerKey(pqKeyID); err != nil {
			r.logger.LogError(err, "Failed to load PQ issuer key, PQ OCSP disabled", nil)
			r.pqEnabled = false
		}
	} else {
		r.pqEnabled = false
	}

	return nil
}

func (r *Responder) loadClassicalIssuerKey(keyID string) error {
	keyData, _, err := r.keyStore.LoadKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA private key: %w", err)
	}
	defer r.secureZero(keyData)

	r.issuerKey, err = pq.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA private key: %w", err)
	}

	certData, err := r.keyStore.LoadCertificate(keyID)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}

	r.issuerCert = cert
	return nil
}

func (r *Responder) loadPQIssuerKey(keyID string) error {
	keyData, _, err := r.keyStore.LoadKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to load PQ intermediate CA private key: %w", err)
	}
	defer r.secureZero(keyData)

	r.pqIssuerKey, err = pq.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse PQ intermediate CA private key: %w", err)
	}

	return nil
}

func (r *Responder) mapRevocationReason(reason string) int {
	reasonMap := map[string]int{
		"unspecified":            ocsp.Unspecified,
		"key_compromise":         ocsp.KeyCompromise,
		"ca_compromise":          ocsp.CACompromise,
		"affiliation_changed":    ocsp.AffiliationChanged,
		"superseded":             ocsp.Superseded,
		"cessation_of_operation": ocsp.CessationOfOperation,
		"certificate_hold":       ocsp.CertificateHold,
		"privilege_withdrawn":    ocsp.PrivilegeWithdrawn,
		"aa_compromise":          ocsp.AACompromise,
		"user_requested":         ocsp.Unspecified,
	}

	if code, exists := reasonMap[reason]; exists {
		return code
	}
	return ocsp.Unspecified
}

func (r *Responder) RefreshCache() error {
	return r.loadIssuerCredentials()
}

func (r *Responder) ValidateConfiguration() error {
	if r.config.KeysPath == "" {
		return fmt.Errorf("keys path not configured")
	}

	if r.keyStore == nil {
		return fmt.Errorf("key store not initialized")
	}

	keyIDs, err := r.keyStore.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var foundIntermediateCA bool
	for _, keyID := range keyIDs {
		metadata, err := r.keyStore.GetKeyMetadata(keyID)
		if err != nil {
			continue
		}
		if metadata.KeyType == "intermediate-ca" {
			foundIntermediateCA = true
			break
		}
	}

	if !foundIntermediateCA {
		return fmt.Errorf("intermediate CA key not found in key store")
	}

	return nil
}

func (r *Responder) ValidatePQCertificate(certPEM []byte, signature []byte, algorithm string) error {
	if !r.pqEnabled || r.pqIssuerKey == nil {
		return fmt.Errorf("PQ validation not available")
	}

	pqPublicKey, err := pq.GetPublicKey(r.pqIssuerKey)
	if err != nil {
		return fmt.Errorf("failed to get PQ public key: %w", err)
	}

	valid := pq.Verify(pqPublicKey, certPEM, signature)
	if !valid {
		return fmt.Errorf("PQ signature verification failed")
	}

	return nil
}

func (r *Responder) GetStatistics() map[string]interface{} {
	stats := make(map[string]interface{})

	var totalRequests, goodResponses, revokedResponses, unknownResponses int

	query := `SELECT 
		COUNT(*) as total,
		COUNT(CASE WHEN status = 'active' THEN 1 END) as good,
		COUNT(CASE WHEN status = 'revoked' THEN 1 END) as revoked,
		COUNT(CASE WHEN status = 'expired' THEN 1 END) as expired
		FROM certificates`

	err := r.db.QueryRow(query).Scan(&totalRequests, &goodResponses, &revokedResponses, &unknownResponses)
	if err != nil {
		stats["error"] = err.Error()
		return stats
	}

	var pqCertificates int
	pqQuery := `SELECT COUNT(*) FROM certificates WHERE algorithms LIKE '%dilithium%' OR algorithms LIKE '%falcon%' OR algorithms LIKE '%sphincs%' OR algorithms LIKE '%hybrid%'`
	r.db.QueryRow(pqQuery).Scan(&pqCertificates)

	stats["total_certificates"] = totalRequests
	stats["good_certificates"] = goodResponses
	stats["revoked_certificates"] = revokedResponses
	stats["expired_certificates"] = unknownResponses
	stats["pq_certificates"] = pqCertificates
	stats["pq_enabled"] = r.pqEnabled
	stats["issuer_loaded"] = r.issuerCert != nil && r.issuerKey != nil
	stats["pq_issuer_loaded"] = r.pqIssuerKey != nil

	if r.issuerCert != nil {
		stats["issuer_subject"] = r.issuerCert.Subject.String()
		stats["issuer_expires"] = r.issuerCert.NotAfter
		stats["issuer_serial"] = r.issuerCert.SerialNumber.String()
	}

	if r.pqEnabled && r.pqIssuerKey != nil {
		stats["pq_algorithm"] = r.getPQAlgorithmFromKey()
	}

	return stats
}

func (r *Responder) HealthCheck() error {
	if err := r.ValidateConfiguration(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	if r.issuerCert == nil || r.issuerKey == nil {
		if err := r.loadIssuerCredentials(); err != nil {
			return fmt.Errorf("failed to load credentials: %w", err)
		}
	}

	if time.Now().After(r.issuerCert.NotAfter) {
		return fmt.Errorf("issuer certificate has expired")
	}

	if time.Now().Add(30*24*time.Hour).After(r.issuerCert.NotAfter) {
		return fmt.Errorf("issuer certificate expires within 30 days")
	}

	if err := r.db.Ping(); err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}

	if r.pqEnabled {
		testData := []byte("ocsp-pq-health-check")
		_, err := r.signWithPQKey(testData)
		if err != nil {
			r.logger.LogError(err, "PQ signing health check failed", nil)
			r.pqEnabled = false
		}
	}

	return nil
}

func (r *Responder) ProcessBulkRequests(requests [][]byte) ([][]byte, error) {
	responses := make([][]byte, len(requests))
	var lastError error

	for i, requestBytes := range requests {
		response, err := r.HandleRequest(requestBytes)
		responses[i] = response
		if err != nil {
			lastError = err
			r.logger.LogError(err, "Failed to process OCSP request", map[string]interface{}{
				"request_index": i,
			})
		}
	}

	if lastError != nil {
		return responses, fmt.Errorf("some requests failed processing: %w", lastError)
	}

	return responses, nil
}

func (r *Responder) UpdateRevocationStatus(serialNumber string, status string, reason string) error {
	query := `UPDATE certificates SET status = ?, revoked_at = CURRENT_TIMESTAMP, 
			  revocation_reason = ?, updated_at = CURRENT_TIMESTAMP 
			  WHERE serial_number = ? AND status = 'active'`

	result, err := r.db.Exec(query, status, reason, serialNumber)
	if err != nil {
		return fmt.Errorf("failed to update revocation status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("certificate not found or already revoked")
	}

	r.logger.LogCertificateEvent("certificate_revocation_updated", serialNumber, 0, map[string]interface{}{
		"new_status": status,
		"reason":     reason,
	})

	return nil
}

func (r *Responder) GetCertificateStatusBySerial(serialNumber string) (*CertificateStatus, error) {
	serialBig := new(big.Int)
	if _, ok := serialBig.SetString(serialNumber, 10); !ok {
		if _, ok := serialBig.SetString(serialNumber, 16); !ok {
			return nil, fmt.Errorf("invalid serial number format")
		}
	}

	return r.getCertificateStatus(serialBig)
}

func (r *Responder) secureZero(data []byte) {
	if len(data) > 0 {
		for i := range data {
			data[i] = 0
		}
	}
}

func (r *Responder) Close() error {
	r.issuerCert = nil
	r.issuerKey = nil
	r.pqIssuerKey = nil
	r.keyStore = nil
	return nil
}

func (r *Responder) ReloadConfiguration() error {
	r.issuerCert = nil
	r.issuerKey = nil
	r.pqIssuerKey = nil
	
	keyStore, err := keymanager.NewEncryptedKeyStore(r.config.KeysPath, r.config.IntermediateCAPassphrase)
	if err != nil {
		return fmt.Errorf("failed to reinitialize key store: %w", err)
	}
	r.keyStore = keyStore

	return r.loadIssuerCredentials()
}

func (r *Responder) GetNextUpdate() time.Time {
	return time.Now().Add(24 * time.Hour)
}

func (r *Responder) GetThisUpdate() time.Time {
	return time.Now()
}