package ocsp

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type Responder struct {
	db     *sql.DB
	config *utils.Config
}

func NewResponder(db *sql.DB, config *utils.Config) *Responder {
	return &Responder{
		db:     db,
		config: config,
	}
}

func (r *Responder) HandleRequest(requestBytes []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP request: %v", err)
	}

	cert, err := r.getCertificateBySerial(req.SerialNumber)
	if err != nil {
		return r.createUnknownResponse(req)
	}

	status := ocsp.Good
	if cert.Status == "revoked" {
		status = ocsp.Revoked
	}

	template := ocsp.Response{
		Status:       status,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	if status == ocsp.Revoked {
		template.RevokedAt = cert.CreatedAt
		template.RevocationReason = ocsp.Unspecified
	}

	issuerCert, err := r.getIssuerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer certificate: %v", err)
	}

	issuerKey, err := r.getIssuerPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer private key: %v", err)
	}

	responseBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, template, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP response: %v", err)
	}

	return responseBytes, nil
}

func (r *Responder) getCertificateBySerial(serialNumber *big.Int) (*storage.Certificate, error) {
	query := `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
			  certificate_pem, private_key_pem, algorithms, not_before, not_after, status, created_at 
			  FROM certificates WHERE serial_number = ?`
	
	var cert storage.Certificate
	var subjectAltNamesJSON, algorithmsJSON string
	err := r.db.QueryRow(query, serialNumber.String()).Scan(&cert.ID, &cert.CustomerID, &cert.SerialNumber, 
		&cert.CommonName, &subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
		&algorithmsJSON, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt)
	
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func (r *Responder) createUnknownResponse(req *ocsp.Request) ([]byte, error) {
	template := ocsp.Response{
		Status:       ocsp.Unknown,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	issuerCert, err := r.getIssuerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer certificate: %v", err)
	}

	issuerKey, err := r.getIssuerPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer private key: %v", err)
	}

	return ocsp.CreateResponse(issuerCert, issuerCert, template, issuerKey)
}

func (r *Responder) getIssuerCertificate() (*x509.Certificate, error) {
	certPath := r.config.KeysPath + "/intermediate-ca.pem"
	certPEM, err := r.readFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

func (r *Responder) getIssuerPrivateKey() (interface{}, error) {
	keyPath := r.config.KeysPath + "/intermediate-ca-key.pem"
	keyPEM, err := r.readFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func (r *Responder) readFile(path string) ([]byte, error) {
	return []byte{}, fmt.Errorf("file reading not implemented")
}