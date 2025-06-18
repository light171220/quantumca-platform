package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"quantumca-platform/internal/crypto/keymanager"
	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/utils"
)

type RootCA struct {
	config         *utils.Config
	certificate    *x509.Certificate
	privateKey     interface{}
	multiPQCKey    *pq.MultiPQCPrivateKey
	keyStore       *keymanager.EncryptedKeyStore
	useMultiPQC    bool
}

func NewRootCA(config *utils.Config) *RootCA {
	return &RootCA{
		config:      config,
		useMultiPQC: true,
	}
}

func (r *RootCA) Initialize() error {
	keyStore, err := keymanager.NewEncryptedKeyStore(r.config.KeysPath, r.config.RootCAPassphrase)
	if err != nil {
		return fmt.Errorf("failed to initialize key store: %w", err)
	}
	r.keyStore = keyStore

	if err := r.loadOrGenerateCA(); err != nil {
		return fmt.Errorf("failed to load or generate root CA: %w", err)
	}

	return nil
}

func (r *RootCA) loadOrGenerateCA() error {
	keyIDs, err := r.keyStore.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var rootCAKeyID string
	for _, keyID := range keyIDs {
		metadata, err := r.keyStore.GetKeyMetadata(keyID)
		if err != nil {
			continue
		}
		if metadata.KeyType == "root-ca" {
			rootCAKeyID = keyID
			break
		}
	}

	if rootCAKeyID != "" {
		return r.loadExistingCA(rootCAKeyID)
	}

	return r.generateNewCA()
}

func (r *RootCA) loadExistingCA(keyID string) error {
	keyData, metadata, err := r.keyStore.LoadKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to load root CA private key: %w", err)
	}
	defer r.secureZero(keyData)

	if metadata.Algorithm == "multi-pqc" {
		r.multiPQCKey, err = pq.ParseMultiPQCPrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("failed to parse multi-PQC private key: %w", err)
		}
		r.useMultiPQC = true
	} else {
		r.privateKey, err = pq.ParsePrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("failed to parse root CA private key: %w", err)
		}
		r.useMultiPQC = false
	}

	certData, err := r.keyStore.LoadCertificate(keyID)
	if err != nil {
		return fmt.Errorf("failed to load root CA certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	r.certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	return nil
}

func (r *RootCA) generateNewCA() error {
	if r.useMultiPQC {
		return r.generateMultiPQCCA()
	}
	return r.generateSinglePQCCA()
}

func (r *RootCA) generateMultiPQCCA() error {
	multiPQCKey, err := pq.GenerateMultiPQCKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate multi-PQC root CA key: %w", err)
	}

	multiPQCPublic, err := multiPQCKey.Public()
	if err != nil {
		return fmt.Errorf("failed to get multi-PQC public key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"QuantumCA Root CA"},
			OrganizationalUnit: []string{"Multi-PQC Root Authority"},
			CommonName:         "QuantumCA Multi-PQC Root Certificate Authority",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, multiPQCPublic.PrimaryKey, multiPQCKey.PrimaryKey)
	if err != nil {
		return fmt.Errorf("failed to create multi-PQC root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	multiPQCPrivateKeyDER, err := pq.MarshalMultiPQCPrivateKey(multiPQCKey)
	if err != nil {
		return fmt.Errorf("failed to marshal multi-PQC private key: %w", err)
	}

	keyID := fmt.Sprintf("root-ca-multi-pqc-%d", time.Now().Unix())
	if err := r.keyStore.StoreKey(keyID, multiPQCPrivateKeyDER, "root-ca", "multi-pqc"); err != nil {
		return fmt.Errorf("failed to store multi-PQC private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := r.keyStore.StoreCertificate(keyID, certPEM); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	r.certificate = cert
	r.multiPQCKey = multiPQCKey
	r.useMultiPQC = true

	r.secureZero(multiPQCPrivateKeyDER)

	return nil
}

func (r *RootCA) generateSinglePQCCA() error {
	privateKey, err := pq.GenerateKey("dilithium5")
	if err != nil {
		return fmt.Errorf("failed to generate root CA private key: %w", err)
	}

	publicKey, err := pq.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"QuantumCA Root CA"},
			OrganizationalUnit: []string{"Quantum-Safe PKI"},
			CommonName:         "QuantumCA Root Certificate Authority",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	privateKeyDER, err := pq.MarshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyID := fmt.Sprintf("root-ca-%d", time.Now().Unix())
	if err := r.keyStore.StoreKey(keyID, privateKeyDER, "root-ca", "dilithium5"); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := r.keyStore.StoreCertificate(keyID, certPEM); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	r.certificate = cert
	r.privateKey = privateKey
	r.useMultiPQC = false

	r.secureZero(privateKeyDER)

	return nil
}

func (r *RootCA) GetCertificate() *x509.Certificate {
	return r.certificate
}

func (r *RootCA) GetPrivateKey() interface{} {
	if r.useMultiPQC {
		return r.multiPQCKey
	}
	return r.privateKey
}

func (r *RootCA) GetCertificatePEM() ([]byte, error) {
	if r.certificate == nil {
		return nil, fmt.Errorf("no certificate available")
	}
	
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: r.certificate.Raw,
	}), nil
}

func (r *RootCA) ValidateCertificateChain(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	if r.certificate == nil {
		return fmt.Errorf("root CA certificate not loaded")
	}

	roots := x509.NewCertPool()
	roots.AddCert(r.certificate)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	return nil
}

func (r *RootCA) SignCertificate(template *x509.Certificate, publicKey interface{}) ([]byte, error) {
	if template == nil {
		return nil, fmt.Errorf("certificate template cannot be nil")
	}

	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	if r.certificate == nil {
		return nil, fmt.Errorf("root CA not properly initialized")
	}

	var signingKey interface{}
	if r.useMultiPQC && r.multiPQCKey != nil {
		signingKey = r.multiPQCKey.PrimaryKey
	} else if r.privateKey != nil {
		signingKey = r.privateKey
	} else {
		return nil, fmt.Errorf("no signing key available")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, r.certificate, publicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	signedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	if err := r.ValidateCertificateChain(signedCert); err != nil {
		return nil, fmt.Errorf("signed certificate failed chain validation: %w", err)
	}

	return certDER, nil
}

func (r *RootCA) SignWithMultiPQC(template *x509.Certificate, publicKey interface{}) ([][]byte, error) {
	if !r.useMultiPQC || r.multiPQCKey == nil {
		return nil, fmt.Errorf("multi-PQC not available")
	}

	if template == nil {
		return nil, fmt.Errorf("certificate template cannot be nil")
	}

	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	var certificates [][]byte

	primaryCert, err := x509.CreateCertificate(rand.Reader, template, r.certificate, publicKey, r.multiPQCKey.PrimaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary certificate: %w", err)
	}
	certificates = append(certificates, primaryCert)

	secondaryCert, err := x509.CreateCertificate(rand.Reader, template, r.certificate, publicKey, r.multiPQCKey.SecondaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create secondary certificate: %w", err)
	}
	certificates = append(certificates, secondaryCert)

	tertiaryCert, err := x509.CreateCertificate(rand.Reader, template, r.certificate, publicKey, r.multiPQCKey.TertiaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tertiary certificate: %w", err)
	}
	certificates = append(certificates, tertiaryCert)

	return certificates, nil
}

func (r *RootCA) IsValidIssuer(cert *x509.Certificate) bool {
	if cert == nil || r.certificate == nil {
		return false
	}

	return cert.Issuer.String() == r.certificate.Subject.String()
}

func (r *RootCA) GetKeyFingerprint() (string, error) {
	if r.certificate == nil {
		return "", fmt.Errorf("root CA certificate not loaded")
	}

	fingerprint := utils.HashPrefix(string(r.certificate.Raw), 16)
	return fingerprint, nil
}

func (r *RootCA) ValidateIntegrity() error {
	if r.certificate == nil {
		return fmt.Errorf("root CA not initialized")
	}

	testMessage := []byte("integrity-test-message")

	if r.useMultiPQC && r.multiPQCKey != nil {
		signature, err := r.multiPQCKey.Sign(testMessage)
		if err != nil {
			return fmt.Errorf("failed to sign test data with multi-PQC: %w", err)
		}

		multiPQCPublic, err := r.multiPQCKey.Public()
		if err != nil {
			return fmt.Errorf("failed to get multi-PQC public key: %w", err)
		}

		if !multiPQCPublic.Verify(testMessage, signature) {
			return fmt.Errorf("multi-PQC signature verification failed - key integrity compromised")
		}
	} else if r.privateKey != nil {
		signature, err := pq.Sign(r.privateKey, testMessage)
		if err != nil {
			return fmt.Errorf("failed to sign test data: %w", err)
		}

		publicKey, err := pq.GetPublicKey(r.privateKey)
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}

		if !pq.Verify(publicKey, testMessage, signature) {
			return fmt.Errorf("signature verification failed - key integrity compromised")
		}
	} else {
		return fmt.Errorf("no private key available for integrity check")
	}

	if time.Now().After(r.certificate.NotAfter) {
		return fmt.Errorf("root CA certificate has expired")
	}

	if time.Now().Add(365*24*time.Hour).After(r.certificate.NotAfter) {
		return fmt.Errorf("root CA certificate expires within one year")
	}

	return nil
}

func (r *RootCA) secureZero(data []byte) {
	if len(data) > 0 {
		for i := range data {
			data[i] = 0
		}
	}
}

func (r *RootCA) GetCertificateInfo() map[string]interface{} {
	if r.certificate == nil {
		return map[string]interface{}{
			"status": "not_initialized",
		}
	}

	var algorithms []string
	if r.useMultiPQC && r.multiPQCKey != nil {
		algorithms = []string{
			"multi-pqc",
			r.multiPQCKey.PrimaryAlgorithm,
			r.multiPQCKey.SecondaryAlgorithm,
			r.multiPQCKey.TertiaryAlgorithm,
		}
	} else {
		algorithms = []string{"dilithium5"}
	}

	return map[string]interface{}{
		"subject":       r.certificate.Subject.String(),
		"serial_number": r.certificate.SerialNumber.String(),
		"not_before":    r.certificate.NotBefore,
		"not_after":     r.certificate.NotAfter,
		"is_ca":         r.certificate.IsCA,
		"max_path_len":  r.certificate.MaxPathLen,
		"key_usage":     r.certificate.KeyUsage,
		"algorithms":    algorithms,
		"multi_pqc":     r.useMultiPQC,
	}
}

func (r *RootCA) IsMultiPQC() bool {
	return r.useMultiPQC
}