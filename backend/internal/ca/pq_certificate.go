package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"time"

	"quantumca-platform/internal/crypto/pq"
)

type PQCertificate struct {
	Version        int                `json:"version"`
	SerialNumber   *big.Int           `json:"serial_number"`
	Subject        pkix.Name          `json:"subject"`
	Issuer         pkix.Name          `json:"issuer"`
	NotBefore      time.Time          `json:"not_before"`
	NotAfter       time.Time          `json:"not_after"`
	PublicKey      []byte             `json:"public_key"`
	KeyUsage       x509.KeyUsage      `json:"key_usage"`
	ExtKeyUsage    []x509.ExtKeyUsage `json:"ext_key_usage"`
	DNSNames       []string           `json:"dns_names"`
	IPAddresses    []net.IP           `json:"ip_addresses"`
	EmailAddresses []string           `json:"email_addresses"`
	Algorithm      string             `json:"algorithm"`
	Extensions     []PQExtension      `json:"extensions"`
	IssuerKeyID    []byte             `json:"issuer_key_id"`
	SubjectKeyID   []byte             `json:"subject_key_id"`
}

type SignedPQCertificate struct {
	Certificate        PQCertificate `json:"certificate"`
	SignatureAlgorithm string        `json:"signature_algorithm"`
	Signature          []byte        `json:"signature"`
	SigningTime        time.Time     `json:"signing_time"`
}

type PQExtension struct {
	ID       []int  `json:"id"`
	Critical bool   `json:"critical"`
	Value    []byte `json:"value"`
}

type PQCertificateRequest struct {
	Subject        pkix.Name          `json:"subject"`
	PublicKey      []byte             `json:"public_key"`
	Algorithm      string             `json:"algorithm"`
	DNSNames       []string           `json:"dns_names"`
	IPAddresses    []net.IP           `json:"ip_addresses"`
	EmailAddresses []string           `json:"email_addresses"`
	KeyUsage       x509.KeyUsage      `json:"key_usage"`
	ExtKeyUsage    []x509.ExtKeyUsage `json:"ext_key_usage"`
	ValidityPeriod time.Duration      `json:"validity_period"`
	Extensions     []PQExtension      `json:"extensions"`
}

func generateSerialNumber() (*big.Int, error) {
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

func (ei *Issuer) marshalPQCertificate(cert *PQCertificate) ([]byte, error) {
	return json.Marshal(cert)
}

func (ei *Issuer) marshalSignedPQCertificate(signedCert *SignedPQCertificate) ([]byte, error) {
	return json.Marshal(signedCert)
}

func (ei *Issuer) signPQCertificate(certBytes []byte, privateKey interface{}) ([]byte, error) {
	signature, err := pq.Sign(privateKey, certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign PQ certificate: %w", err)
	}
	return signature, nil
}

func (ei *Issuer) createPQCertificateFromTemplate(template *x509.Certificate, publicKey interface{}, algorithm string) (*PQCertificate, error) {
	pubKeyBytes, err := pq.MarshalPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PQ public key: %w", err)
	}

	pqCert := &PQCertificate{
		Version:        1,
		SerialNumber:   template.SerialNumber,
		Subject:        template.Subject,
		Issuer:         template.Issuer,
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
		PublicKey:      pubKeyBytes,
		Algorithm:      algorithm,
		KeyUsage:       template.KeyUsage,
		ExtKeyUsage:    template.ExtKeyUsage,
		DNSNames:       template.DNSNames,
		IPAddresses:    template.IPAddresses,
		EmailAddresses: template.EmailAddresses,
		Extensions:     []PQExtension{},
	}

	subjectKeyID, err := ei.calculatePQKeyID(publicKey)
	if err == nil {
		pqCert.SubjectKeyID = []byte(subjectKeyID)
	}

	if ei.intermediateCA != nil && ei.intermediateCA.GetCertificate() != nil {
		pqCert.Issuer = ei.intermediateCA.GetCertificate().Subject
		
		issuerKeyID, err := ei.calculateIssuerKeyID()
		if err == nil && issuerKeyID != nil {
			pqCert.IssuerKeyID = issuerKeyID
		}
	}

	return pqCert, nil
}

func (ei *Issuer) calculateIssuerKeyID() ([]byte, error) {
	if ei.intermediateCA != nil && ei.intermediateCA.GetCertificate() != nil {
		pubKey := ei.intermediateCA.GetCertificate().PublicKey
		keyID, err := ei.calculatePQKeyID(pubKey)
		if err != nil {
			return nil, err
		}
		return []byte(keyID), nil
	}
	if ei.rootCA != nil && ei.rootCA.GetCertificate() != nil {
		pubKey := ei.rootCA.GetCertificate().PublicKey
		keyID, err := ei.calculatePQKeyID(pubKey)
		if err != nil {
			return nil, err
		}
		return []byte(keyID), nil
	}
	return nil, fmt.Errorf("issuer public key not found")
}

func (ei *Issuer) verifyPQCertificate(signedCert *SignedPQCertificate, issuerPublicKey interface{}) error {
	certBytes, err := ei.marshalPQCertificate(&signedCert.Certificate)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate for verification: %w", err)
	}

	valid := pq.Verify(issuerPublicKey, certBytes, signedCert.Signature)
	if !valid {
		return fmt.Errorf("PQ certificate signature verification failed")
	}

	if time.Now().Before(signedCert.Certificate.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}

	if time.Now().After(signedCert.Certificate.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	return nil
}

func (ei *Issuer) getIntermediatePQCertificate() *SignedPQCertificate {
	if ei.intermediateCA == nil {
		return nil
	}
	
	cert := ei.intermediateCA.GetCertificate()
	if cert == nil {
		return nil
	}

	serialNumber, _ := generateSerialNumber()
	pqCert := &PQCertificate{
		Version:      1,
		SerialNumber: serialNumber,
		Subject:      cert.Subject,
		Issuer:       cert.Issuer,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Algorithm:    "dilithium3",
		KeyUsage:     cert.KeyUsage,
		ExtKeyUsage:  cert.ExtKeyUsage,
		Extensions:   []PQExtension{},
	}

	pubKeyBytes, err := pq.MarshalPublicKey(cert.PublicKey)
	if err == nil {
		pqCert.PublicKey = pubKeyBytes
	}

	signedCert := &SignedPQCertificate{
		Certificate:        *pqCert,
		SignatureAlgorithm: "dilithium3",
		Signature:          cert.Signature,
		SigningTime:        time.Now(),
	}

	return signedCert
}

func (ei *Issuer) getRootPQCertificate() *SignedPQCertificate {
	if ei.rootCA == nil {
		return nil
	}
	
	cert := ei.rootCA.GetCertificate()
	if cert == nil {
		return nil
	}

	serialNumber, _ := generateSerialNumber()
	pqCert := &PQCertificate{
		Version:      1,
		SerialNumber: serialNumber,
		Subject:      cert.Subject,
		Issuer:       cert.Issuer,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Algorithm:    "dilithium5",
		KeyUsage:     cert.KeyUsage,
		ExtKeyUsage:  cert.ExtKeyUsage,
		Extensions:   []PQExtension{},
	}

	pubKeyBytes, err := pq.MarshalPublicKey(cert.PublicKey)
	if err == nil {
		pqCert.PublicKey = pubKeyBytes
	}

	signedCert := &SignedPQCertificate{
		Certificate:        *pqCert,
		SignatureAlgorithm: "dilithium5",
		Signature:          cert.Signature,
		SigningTime:        time.Now(),
	}

	return signedCert
}

func (ei *Issuer) exportPQCertificateToPEM(signedCert *SignedPQCertificate) ([]byte, error) {
	certBytes, err := ei.marshalSignedPQCertificate(signedCert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed certificate: %w", err)
	}

	pemData := fmt.Sprintf("-----BEGIN PQ CERTIFICATE-----\n%s\n-----END PQ CERTIFICATE-----\n", string(certBytes))
	return []byte(pemData), nil
}

func (ei *Issuer) parsePQCertificateFromPEM(pemData []byte) (*SignedPQCertificate, error) {
	startMarker := "-----BEGIN PQ CERTIFICATE-----"
	endMarker := "-----END PQ CERTIFICATE-----"
	
	pemStr := string(pemData)
	startIdx := len(startMarker)
	endIdx := len(pemStr) - len(endMarker)
	
	if startIdx >= endIdx {
		return nil, fmt.Errorf("invalid PEM format")
	}
	
	certData := pemStr[startIdx:endIdx]
	
	var signedCert SignedPQCertificate
	if err := json.Unmarshal([]byte(certData), &signedCert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PQ certificate: %w", err)
	}

	return &signedCert, nil
}

func (ei *Issuer) createPQCertificateFromRequest(req *PQCertificateRequest, issuerKey interface{}) (*SignedPQCertificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	cert := &PQCertificate{
		Version:        1,
		SerialNumber:   serialNumber,
		Subject:        req.Subject,
		NotBefore:      now,
		NotAfter:       now.Add(req.ValidityPeriod),
		PublicKey:      req.PublicKey,
		Algorithm:      req.Algorithm,
		KeyUsage:       req.KeyUsage,
		ExtKeyUsage:    req.ExtKeyUsage,
		DNSNames:       req.DNSNames,
		IPAddresses:    req.IPAddresses,
		EmailAddresses: req.EmailAddresses,
		Extensions:     req.Extensions,
	}

	if ei.intermediateCA != nil && ei.intermediateCA.GetCertificate() != nil {
		cert.Issuer = ei.intermediateCA.GetCertificate().Subject
	}

	certBytes, err := ei.marshalPQCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	signature, err := ei.signPQCertificate(certBytes, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	signedCert := &SignedPQCertificate{
		Certificate:        *cert,
		SignatureAlgorithm: req.Algorithm,
		Signature:          signature,
		SigningTime:        now,
	}

	return signedCert, nil
}