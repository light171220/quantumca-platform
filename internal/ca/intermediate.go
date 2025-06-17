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

type IntermediateCA struct {
	config      *utils.Config
	rootCA      *RootCA
	certificate *x509.Certificate
	privateKey  interface{}
	keyStore    *keymanager.EncryptedKeyStore
}

func NewIntermediateCA(config *utils.Config, rootCA *RootCA) *IntermediateCA {
	return &IntermediateCA{
		config: config,
		rootCA: rootCA,
	}
}

func (i *IntermediateCA) Initialize() error {
	keyStore, err := keymanager.NewEncryptedKeyStore(i.config.KeysPath, i.config.IntermediateCAPassphrase)
	if err != nil {
		return fmt.Errorf("failed to initialize key store: %w", err)
	}
	i.keyStore = keyStore

	if err := i.loadOrGenerateCA(); err != nil {
		return fmt.Errorf("failed to load or generate intermediate CA: %w", err)
	}

	return nil
}

func (i *IntermediateCA) loadOrGenerateCA() error {
	keyIDs, err := i.keyStore.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var intermediateKeyID string
	for _, keyID := range keyIDs {
		metadata, err := i.keyStore.GetKeyMetadata(keyID)
		if err != nil {
			continue
		}
		if metadata.KeyType == "intermediate-ca" {
			intermediateKeyID = keyID
			break
		}
	}

	if intermediateKeyID != "" {
		return i.loadExistingCA(intermediateKeyID)
	}

	return i.generateNewCA()
}

func (i *IntermediateCA) loadExistingCA(keyID string) error {
	keyData, _, err := i.keyStore.LoadKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA private key: %w", err)
	}
	defer i.secureZero(keyData)

	i.privateKey, err = pq.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA private key: %w", err)
	}

	certData, err := i.keyStore.LoadCertificate(keyID)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	i.certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}

	if err := i.validateCertificateChain(); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}

func (i *IntermediateCA) generateNewCA() error {
	privateKey, err := pq.GenerateKey("dilithium3")
	if err != nil {
		return fmt.Errorf("failed to generate intermediate CA private key: %w", err)
	}

	publicKey, err := pq.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"QuantumCA Intermediate CA"},
			OrganizationalUnit: []string{"Quantum-Safe PKI"},
			CommonName:         "QuantumCA Intermediate Certificate Authority",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := i.rootCA.SignCertificate(template, publicKey)
	if err != nil {
		return fmt.Errorf("failed to sign intermediate CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	if err := i.rootCA.ValidateCertificateChain(cert); err != nil {
		return fmt.Errorf("generated certificate failed chain validation: %w", err)
	}

	privateKeyDER, err := pq.MarshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyID := fmt.Sprintf("intermediate-ca-%d", time.Now().Unix())
	if err := i.keyStore.StoreKey(keyID, privateKeyDER, "intermediate-ca", "dilithium3"); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := i.keyStore.StoreCertificate(keyID, certPEM); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	i.certificate = cert
	i.privateKey = privateKey

	i.secureZero(privateKeyDER)

	return nil
}

func (i *IntermediateCA) GetCertificate() *x509.Certificate {
	return i.certificate
}

func (i *IntermediateCA) GetPrivateKey() interface{} {
	return i.privateKey
}

func (i *IntermediateCA) GetCertificatePEM() ([]byte, error) {
	if i.certificate == nil {
		return nil, fmt.Errorf("no certificate available")
	}
	
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: i.certificate.Raw,
	}), nil
}

func (i *IntermediateCA) ValidateCertificateChain(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	if i.certificate == nil {
		return fmt.Errorf("intermediate CA certificate not loaded")
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(i.certificate)

	roots := x509.NewCertPool()
	if i.rootCA != nil && i.rootCA.GetCertificate() != nil {
		roots.AddCert(i.rootCA.GetCertificate())
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	for _, chain := range chains {
		if len(chain) < 2 {
			return fmt.Errorf("invalid chain length: %d", len(chain))
		}

		endEntity := chain[0]
		intermediate := chain[1]

		if err := endEntity.CheckSignatureFrom(intermediate); err != nil {
			return fmt.Errorf("end entity signature verification failed: %w", err)
		}

		if len(chain) > 2 {
			root := chain[2]
			if err := intermediate.CheckSignatureFrom(root); err != nil {
				return fmt.Errorf("intermediate signature verification failed: %w", err)
			}
		}
	}

	return nil
}

func (i *IntermediateCA) validateCertificateChain() error {
	if i.certificate == nil {
		return fmt.Errorf("intermediate CA certificate not loaded")
	}

	return i.rootCA.ValidateCertificateChain(i.certificate)
}

func (i *IntermediateCA) SignCertificate(template *x509.Certificate, publicKey interface{}) ([]byte, error) {
	if template == nil {
		return nil, fmt.Errorf("certificate template cannot be nil")
	}

	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	if i.certificate == nil || i.privateKey == nil {
		return nil, fmt.Errorf("intermediate CA not properly initialized")
	}

	template.Issuer = i.certificate.Subject

	certDER, err := x509.CreateCertificate(rand.Reader, template, i.certificate, publicKey, i.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	signedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	if err := i.ValidateCertificateChain(signedCert); err != nil {
		return nil, fmt.Errorf("signed certificate failed chain validation: %w", err)
	}

	return certDER, nil
}

func (i *IntermediateCA) IsValidIssuer(cert *x509.Certificate) bool {
	if cert == nil || i.certificate == nil {
		return false
	}

	return cert.Issuer.String() == i.certificate.Subject.String()
}

func (i *IntermediateCA) GetKeyFingerprint() (string, error) {
	if i.certificate == nil {
		return "", fmt.Errorf("intermediate CA certificate not loaded")
	}

	fingerprint := utils.HashPrefix(string(i.certificate.Raw), 16)
	return fingerprint, nil
}

func (i *IntermediateCA) ValidateIntegrity() error {
	if i.certificate == nil || i.privateKey == nil {
		return fmt.Errorf("intermediate CA not initialized")
	}

	testData := []byte("integrity-test-message")
	signature, err := pq.Sign(i.privateKey, testData)
	if err != nil {
		return fmt.Errorf("failed to sign test data: %w", err)
	}

	publicKey, err := pq.GetPublicKey(i.privateKey)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	if !pq.Verify(publicKey, testData, signature) {
		return fmt.Errorf("signature verification failed - key integrity compromised")
	}

	if time.Now().After(i.certificate.NotAfter) {
		return fmt.Errorf("intermediate CA certificate has expired")
	}

	if time.Now().Add(90*24*time.Hour).After(i.certificate.NotAfter) {
		return fmt.Errorf("intermediate CA certificate expires within 90 days")
	}

	if err := i.validateCertificateChain(); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}

func (i *IntermediateCA) GetCertificateChain() ([]*x509.Certificate, error) {
	var chain []*x509.Certificate

	if i.certificate != nil {
		chain = append(chain, i.certificate)
	}

	if i.rootCA != nil && i.rootCA.GetCertificate() != nil {
		chain = append(chain, i.rootCA.GetCertificate())
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates in chain")
	}

	return chain, nil
}

func (i *IntermediateCA) secureZero(data []byte) {
	if len(data) > 0 {
		for i := range data {
			data[i] = 0
		}
	}
}

func (i *IntermediateCA) GetCertificateInfo() map[string]interface{} {
	if i.certificate == nil {
		return map[string]interface{}{
			"status": "not_initialized",
		}
	}

	return map[string]interface{}{
		"subject":       i.certificate.Subject.String(),
		"issuer":        i.certificate.Issuer.String(),
		"serial_number": i.certificate.SerialNumber.String(),
		"not_before":    i.certificate.NotBefore,
		"not_after":     i.certificate.NotAfter,
		"is_ca":         i.certificate.IsCA,
		"max_path_len":  i.certificate.MaxPathLen,
		"key_usage":     i.certificate.KeyUsage,
		"algorithms":    []string{"dilithium3"},
	}
}