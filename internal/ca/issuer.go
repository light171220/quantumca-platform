package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
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
	UseHybrid        bool
}

type CertificateResponse struct {
	SerialNumber      string
	CertificatePEM    string
	PrivateKeyPEM     string
	PQCertificatePEM  string
	PQPrivateKeyPEM   string
	Algorithms        []string
	NotBefore         time.Time
	NotAfter          time.Time
	Fingerprint       string
	KeyID             string
	IsHybrid          bool
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
	UseHybrid    bool
}

type HybridKeyPair struct {
	ClassicalPrivate interface{}
	ClassicalPublic  interface{}
	PQPrivate        interface{}
	PQPublic         interface{}
}

func NewIssuer(config *utils.Config) *Issuer {
	rootCA := NewRootCA(config)
	intermediateCA := NewIntermediateCA(config, rootCA)
	validator := NewCertificateValidator(config, utils.NewLogger("info"))
	
	rootCA.Initialize()
	intermediateCA.Initialize()

	return &Issuer{
		config:         config,
		rootCA:         rootCA,
		intermediateCA: intermediateCA,
		validator:      validator,
	}
}

func (ei *Issuer) IssueCertificate(req *CertificateRequest) (*CertificateResponse, error) {
	if err := ei.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid certificate request: %w", err)
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "rsa2048"
	}

	var response *CertificateResponse
	var err error

	if req.UseHybrid || ei.isPQAlgorithm(algorithm) {
		response, err = ei.issueHybridCertificate(req, algorithm)
	} else {
		response, err = ei.issueClassicalCertificate(req, algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	return response, nil
}

func (ei *Issuer) issueClassicalCertificate(req *CertificateRequest, algorithm string) (*CertificateResponse, error) {
	var privateKey interface{}
	var err error

	switch algorithm {
	case "rsa2048":
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa4096":
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa-p256":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported classical algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	publicKey := ei.getPublicKey(privateKey)
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	subject := ei.buildSubject(req)
	template := ei.buildCertificateTemplate(req, subject, serialNumber)

	certDER, err := ei.createClassicalCertificate(template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
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

	keyID, err := ei.calculateClassicalKeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate key ID: %w", err)
	}

	return &CertificateResponse{
		SerialNumber:   serialNumber.String(),
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		Algorithms:     []string{algorithm},
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
		Fingerprint:    fingerprint,
		KeyID:          keyID,
		IsHybrid:       false,
	}, nil
}

func (ei *Issuer) issueHybridCertificate(req *CertificateRequest, algorithm string) (*CertificateResponse, error) {
	hybridKeys, err := ei.generateHybridKeyPair(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hybrid keys: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	subject := ei.buildSubject(req)
	template := ei.buildCertificateTemplate(req, subject, serialNumber)

	classicalCertDER, err := ei.createClassicalCertificate(template, hybridKeys.ClassicalPublic, hybridKeys.ClassicalPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to create classical certificate: %w", err)
	}

	pqCertDER, err := ei.createPQCertificate(template, hybridKeys.PQPublic, hybridKeys.PQPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to create PQ certificate: %w", err)
	}

	classicalCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: classicalCertDER,
	})

	pqCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PQ CERTIFICATE",
		Bytes: pqCertDER,
	})

	classicalKeyDER, err := x509.MarshalPKCS8PrivateKey(hybridKeys.ClassicalPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal classical private key: %w", err)
	}

	classicalKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: classicalKeyDER,
	})

	pqKeyDER, err := pq.MarshalPrivateKey(hybridKeys.PQPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PQ private key: %w", err)
	}

	pqKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PQ PRIVATE KEY",
		Bytes: pqKeyDER,
	})

	fingerprint, err := calculateFingerprint(classicalCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate fingerprint: %w", err)
	}

	keyID, err := ei.calculateClassicalKeyID(hybridKeys.ClassicalPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate key ID: %w", err)
	}

	return &CertificateResponse{
		SerialNumber:     serialNumber.String(),
		CertificatePEM:   string(classicalCertPEM),
		PrivateKeyPEM:    string(classicalKeyPEM),
		PQCertificatePEM: string(pqCertPEM),
		PQPrivateKeyPEM:  string(pqKeyPEM),
		Algorithms:       []string{"hybrid", algorithm},
		NotBefore:        template.NotBefore,
		NotAfter:         template.NotAfter,
		Fingerprint:      fingerprint,
		KeyID:            keyID,
		IsHybrid:         true,
	}, nil
}

func (ei *Issuer) generateHybridKeyPair(algorithm string) (*HybridKeyPair, error) {
	classicalPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	var pqPrivate interface{}
	if ei.isPQAlgorithm(algorithm) {
		pqPrivate, err = pq.GenerateKey(algorithm)
	} else {
		pqPrivate, err = pq.GenerateKey("dilithium2")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQ key: %w", err)
	}

	pqPublic, err := pq.GetPublicKey(pqPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to get PQ public key: %w", err)
	}

	return &HybridKeyPair{
		ClassicalPrivate: classicalPrivate,
		ClassicalPublic:  &classicalPrivate.PublicKey,
		PQPrivate:        pqPrivate,
		PQPublic:         pqPublic,
	}, nil
}

func (ei *Issuer) createClassicalCertificate(template *x509.Certificate, publicKey, privateKey interface{}) ([]byte, error) {
	parent := ei.intermediateCA.GetCertificate()
	parentKey := ei.intermediateCA.GetPrivateKey()

	if parent == nil || parentKey == nil {
		return nil, fmt.Errorf("intermediate CA not available")
	}

	return x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
}

func (ei *Issuer) createPQCertificate(template *x509.Certificate, publicKey, privateKey interface{}) ([]byte, error) {
	pqCert := &PQCertificate{
		Version:      1,
		SerialNumber: template.SerialNumber,
		Subject:      template.Subject,
		NotBefore:    template.NotBefore,
		NotAfter:     template.NotAfter,
		KeyUsage:     template.KeyUsage,
		ExtKeyUsage:  template.ExtKeyUsage,
		DNSNames:     template.DNSNames,
		IPAddresses:  template.IPAddresses,
	}

	pubKeyBytes, err := pq.MarshalPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PQ public key: %w", err)
	}
	pqCert.PublicKey = pubKeyBytes

	certBytes, err := ei.marshalPQCertificate(pqCert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PQ certificate: %w", err)
	}

	signature, err := ei.signPQCertificate(certBytes, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign PQ certificate: %w", err)
	}

	signedCert := &SignedPQCertificate{
		Certificate: *pqCert,
		Signature:   signature,
	}

	return ei.marshalSignedPQCertificate(signedCert)
}

func (ei *Issuer) getPublicKey(privateKey interface{}) interface{} {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		return nil
	}
}

func (ei *Issuer) calculateClassicalKeyID(publicKey interface{}) (string, error) {
	var pubKeyBytes []byte
	var err error

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(key)
	case *ecdsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(key)
	default:
		return "", fmt.Errorf("unsupported public key type")
	}

	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(pubKeyBytes)
	return fmt.Sprintf("%x", hash[:8]), nil
}

func (ei *Issuer) isPQAlgorithm(algorithm string) bool {
	pqAlgorithms := []string{
		"dilithium2", "dilithium3", "dilithium5",
		"falcon512", "falcon1024",
		"sphincs-sha256-128f", "sphincs-sha256-128s",
		"sphincs-sha256-192f", "sphincs-sha256-256f",
		"kyber512", "kyber768", "kyber1024",
	}

	for _, alg := range pqAlgorithms {
		if algorithm == alg {
			return true
		}
	}
	return false
}

func (ei *Issuer) IssueIntermediateCA(req *IntermediateCARequest) (*CertificateResponse, error) {
	if err := ei.validateIntermediateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid intermediate CA request: %w", err)
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "rsa4096"
	}

	var response *CertificateResponse
	var err error

	if req.UseHybrid || ei.isPQAlgorithm(algorithm) {
		response, err = ei.issueHybridIntermediateCA(req, algorithm)
	} else {
		response, err = ei.issueClassicalIntermediateCA(req, algorithm)
	}

	return response, err
}

func (ei *Issuer) issueClassicalIntermediateCA(req *IntermediateCARequest, algorithm string) (*CertificateResponse, error) {
	var privateKey interface{}
	var err error

	switch algorithm {
	case "rsa4096":
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa-p384":
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported algorithm for intermediate CA: %s", algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate CA key: %w", err)
	}

	publicKey := ei.getPublicKey(privateKey)
	serialNumber, err := generateSerialNumber()
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

	certDER, err := ei.createCertificateWithRoot(template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
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

	keyID, err := ei.calculateClassicalKeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate key ID: %w", err)
	}

	return &CertificateResponse{
		SerialNumber:   serialNumber.String(),
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		Algorithms:     []string{algorithm},
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
		Fingerprint:    fingerprint,
		KeyID:          keyID,
		IsHybrid:       false,
	}, nil
}

func (ei *Issuer) issueHybridIntermediateCA(req *IntermediateCARequest, algorithm string) (*CertificateResponse, error) {
	return nil, fmt.Errorf("hybrid intermediate CA not yet implemented")
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

	return nil
}

func (ei *Issuer) isValidAlgorithm(algorithm string) bool {
	validAlgorithms := []string{
		"rsa2048", "rsa4096", "ecdsa-p256", "ecdsa-p384",
		"dilithium2", "dilithium3", "dilithium5",
		"falcon512", "falcon1024",
		"sphincs-sha256-128f", "sphincs-sha256-128s",
		"sphincs-sha256-192f", "sphincs-sha256-256f",
		"kyber512", "kyber768", "kyber1024",
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

func (ei *Issuer) createCertificateWithRoot(template *x509.Certificate, publicKey, privateKey interface{}) ([]byte, error) {
	parent := ei.rootCA.GetCertificate()
	parentKey := ei.rootCA.GetPrivateKey()

	return ei.createCertificateWithParent(template, publicKey, privateKey, parent, parentKey)
}

func (ei *Issuer) createCertificateWithParent(template *x509.Certificate, publicKey, privateKey interface{}, parent *x509.Certificate, parentKey interface{}) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func calculateFingerprint(certDER []byte) (string, error) {
	hash := sha256.Sum256(certDER)
	return fmt.Sprintf("%x", hash), nil
}