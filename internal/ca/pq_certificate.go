package ca

import (
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
	ID       []int `json:"id"`
	Critical bool  `json:"critical"`
	Value    []byte `json:"value"`
}

type PQCertificateChain struct {
	EndEntity     SignedPQCertificate   `json:"end_entity"`
	Intermediates []SignedPQCertificate `json:"intermediates"`
	Root          SignedPQCertificate   `json:"root"`
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
		pqCert.SubjectKeyID = subjectKeyID
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

func (ei *Issuer) calculatePQKeyID(publicKey interface{}) ([]byte, error) {
	pubKeyBytes, err := pq.MarshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	if len(pubKeyBytes) < 20 {
		return pubKeyBytes, nil
	}
	return pubKeyBytes[:20], nil
}

func (ei *Issuer) calculateIssuerKeyID() ([]byte, error) {
	if ei.intermediateCA != nil && ei.intermediateCA.GetCertificate() != nil {
		pubKey := ei.intermediateCA.GetCertificate().PublicKey
		return ei.calculatePQKeyID(pubKey)
	}
	if ei.rootCA != nil && ei.rootCA.GetCertificate() != nil {
		pubKey := ei.rootCA.GetCertificate().PublicKey
		return ei.calculatePQKeyID(pubKey)
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

func (ei *Issuer) buildPQCertificateChain(endEntity *SignedPQCertificate) (*PQCertificateChain, error) {
	chain := &PQCertificateChain{
		EndEntity:     *endEntity,
		Intermediates: []SignedPQCertificate{},
	}

	intermediateCert := ei.getIntermediatePQCertificate()
	if intermediateCert != nil {
		chain.Intermediates = append(chain.Intermediates, *intermediateCert)
	}

	rootCert := ei.getRootPQCertificate()
	if rootCert != nil {
		chain.Root = *rootCert
	}

	return chain, nil
}

func (ei *Issuer) getIntermediatePQCertificate() *SignedPQCertificate {
	return nil
}

func (ei *Issuer) getRootPQCertificate() *SignedPQCertificate {
	return nil
}

func (ei *Issuer) validatePQCertificateChain(chain *PQCertificateChain) error {
	if len(chain.Intermediates) == 0 {
		return fmt.Errorf("no intermediate certificates in chain")
	}

	if err := ei.verifyPQCertificate(&chain.EndEntity, chain.Intermediates[0].Certificate.PublicKey); err != nil {
		return fmt.Errorf("end entity certificate verification failed: %w", err)
	}

	for i, intermediate := range chain.Intermediates {
		var issuerKey interface{}
		if i < len(chain.Intermediates)-1 {
			issuerKey = chain.Intermediates[i+1].Certificate.PublicKey
		} else {
			issuerKey = chain.Root.Certificate.PublicKey
		}

		if err := ei.verifyPQCertificate(&intermediate, issuerKey); err != nil {
			return fmt.Errorf("intermediate certificate %d verification failed: %w", i, err)
		}
	}

	return nil
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
	start := len(startMarker)
	end := len(pemStr) - len(endMarker)
	
	if start >= end {
		return nil, fmt.Errorf("invalid PEM format")
	}
	
	certData := pemStr[start:end]
	
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