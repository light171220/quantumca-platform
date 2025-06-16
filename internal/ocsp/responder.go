package ocsp

import (
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"

	"golang.org/x/crypto/ocsp"
)

type Responder struct {
	db           *sql.DB
	config       *utils.Config
	issuerCert   *x509.Certificate
	issuerKey    interface{}
	caCertCache  map[string]*x509.Certificate
	caKeyCache   map[string]interface{}
}

type CertificateStatus struct {
	Status       int
	SerialNumber *big.Int
	ThisUpdate   time.Time
	NextUpdate   time.Time
	RevokedAt    *time.Time
	Reason       int
}

func NewResponder(db *sql.DB, config *utils.Config) *Responder {
	return &Responder{
		db:          db,
		config:      config,
		caCertCache: make(map[string]*x509.Certificate),
		caKeyCache:  make(map[string]interface{}),
	}
}

func (r *Responder) Initialize() error {
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

	responseBytes, err := r.createOCSPResponse(&template)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP response: %w", err)
	}

	return responseBytes, nil
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

	return r.createOCSPResponse(&template)
}

func (r *Responder) createOCSPResponse(template *ocsp.Response) ([]byte, error) {
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
	certPath := filepath.Join(r.config.KeysPath, "intermediate-ca.pem")
	keyPath := filepath.Join(r.config.KeysPath, "intermediate-ca-key.pem")

	cert, err := r.loadCertificateFromFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to load issuer certificate: %w", err)
	}

	key, err := r.loadPrivateKeyFromFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to load issuer private key: %w", err)
	}

	r.issuerCert = cert
	r.issuerKey = key

	return nil
}

func (r *Responder) loadCertificateFromFile(path string) (*x509.Certificate, error) {
	if cached, exists := r.caCertCache[path]; exists {
		return cached, nil
	}

	certPEM, err := r.readSecureFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	r.caCertCache[path] = cert
	return cert, nil
}

func (r *Responder) loadPrivateKeyFromFile(path string) (interface{}, error) {
	if cached, exists := r.caKeyCache[path]; exists {
		return cached, nil
	}

	keyPEM, err := r.readSecureFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	key, err := r.parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	r.caKeyCache[path] = key
	return key, nil
}

func (r *Responder) parsePrivateKey(keyData []byte) (interface{}, error) {
	key, err := x509.ParsePKCS8PrivateKey(keyData)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParsePKCS1PrivateKey(keyData)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParseECPrivateKey(keyData)
	if err == nil {
		return key, nil
	}

	pqKey, err := pq.ParsePrivateKey(keyData)
	if err == nil {
		return pqKey, nil
	}

	return nil, fmt.Errorf("unable to parse private key")
}

func (r *Responder) readSecureFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("file %s has insecure permissions: %v", path, info.Mode().Perm())
	}

	if info.Size() > 10*1024*1024 {
		return nil, fmt.Errorf("file %s is too large: %d bytes", path, info.Size())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("file %s is empty", path)
	}

	return data, nil
}

func (r *Responder) mapRevocationReason(reason string) int {
	reasonMap := map[string]int{
		"unspecified":          ocsp.Unspecified,
		"key_compromise":       ocsp.KeyCompromise,
		"ca_compromise":        ocsp.CACompromise,
		"affiliation_changed":  ocsp.AffiliationChanged,
		"superseded":          ocsp.Superseded,
		"cessation_of_operation": ocsp.CessationOfOperation,
		"certificate_hold":     ocsp.CertificateHold,
		"privilege_withdrawn":  ocsp.PrivilegeWithdrawn,
		"aa_compromise":       ocsp.AACompromise,
		"user_requested":      ocsp.Unspecified,
	}

	if code, exists := reasonMap[reason]; exists {
		return code
	}
	return ocsp.Unspecified
}

func (r *Responder) RefreshCache() error {
	r.caCertCache = make(map[string]*x509.Certificate)
	r.caKeyCache = make(map[string]interface{})
	return r.loadIssuerCredentials()
}

func (r *Responder) ValidateConfiguration() error {
	if r.config.KeysPath == "" {
		return fmt.Errorf("keys path not configured")
	}

	certPath := filepath.Join(r.config.KeysPath, "intermediate-ca.pem")
	keyPath := filepath.Join(r.config.KeysPath, "intermediate-ca-key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("issuer certificate not found: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("issuer private key not found: %s", keyPath)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		return fmt.Errorf("failed to stat private key file: %w", err)
	}

	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private key file has insecure permissions: %v", info.Mode().Perm())
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

	stats["total_certificates"] = totalRequests
	stats["good_certificates"] = goodResponses
	stats["revoked_certificates"] = revokedResponses
	stats["expired_certificates"] = unknownResponses
	stats["cache_size"] = len(r.caCertCache) + len(r.caKeyCache)
	stats["issuer_loaded"] = r.issuerCert != nil && r.issuerKey != nil

	if r.issuerCert != nil {
		stats["issuer_subject"] = r.issuerCert.Subject.String()
		stats["issuer_expires"] = r.issuerCert.NotAfter
		stats["issuer_serial"] = r.issuerCert.SerialNumber.String()
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

	return nil
}

func (r *Responder) ProcessBulkRequests(requests [][]byte) ([][]byte, error) {
	responses := make([][]byte, len(requests))
	errors := make([]error, len(requests))

	for i, requestBytes := range requests {
		response, err := r.HandleRequest(requestBytes)
		responses[i] = response
		errors[i] = err
	}

	var hasErrors bool
	for _, err := range errors {
		if err != nil {
			hasErrors = true
			break
		}
	}

	if hasErrors {
		return responses, fmt.Errorf("some requests failed processing")
	}

	return responses, nil
}

func (r *Responder) Close() error {
	r.caCertCache = nil
	r.caKeyCache = nil
	r.issuerCert = nil
	r.issuerKey = nil
	return nil
}