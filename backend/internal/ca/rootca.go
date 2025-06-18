package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
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
	dummyRSAKey    *rsa.PrivateKey
}

type RSASignerWrapper struct {
	rsaKey *rsa.PrivateKey
}

func (s *RSASignerWrapper) Public() crypto.PublicKey {
	return &s.rsaKey.PublicKey
}

func (s *RSASignerWrapper) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.rsaKey.Sign(rand, digest, opts)
}

func NewRootCA(config *utils.Config) *RootCA {
	dummyKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &RootCA{
		config:      config,
		useMultiPQC: true,
		dummyRSAKey: dummyKey,
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

	certDER, err := r.createSelfSignedCertificateWithPQReplacement(template, multiPQCKey)
	if err != nil {
		return fmt.Errorf("failed to create multi-PQC root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	r.certificate = cert

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

	certDER, err := r.createSelfSignedCertificateWithPQReplacement(template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	r.certificate = cert

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

	r.privateKey = privateKey
	r.useMultiPQC = false

	r.secureZero(privateKeyDER)

	return nil
}

func (r *RootCA) createSelfSignedCertificateWithPQReplacement(template *x509.Certificate, pqKey interface{}) ([]byte, error) {
	template.Issuer = template.Subject

	rsaSigner := &RSASignerWrapper{rsaKey: r.dummyRSAKey}
	
	rsaCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &r.dummyRSAKey.PublicKey, rsaSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA certificate: %w", err)
	}

	pqCertDER, err := r.replaceCertificateSignatureWithPQ(rsaCertDER, pqKey)
	if err != nil {
		return nil, fmt.Errorf("failed to replace with PQ signature: %w", err)
	}

	return pqCertDER, nil
}

func (r *RootCA) replaceCertificateSignatureWithPQ(rsaCertDER []byte, pqKey interface{}) ([]byte, error) {
	var cert struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}

	_, err := asn1.Unmarshal(rsaCertDER, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
	}

	pqSignature, err := pq.Sign(pqKey, cert.TBSCertificate.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create PQ signature: %w", err)
	}

	cert.SignatureValue = asn1.BitString{
		Bytes:     pqSignature,
		BitLength: len(pqSignature) * 8,
	}

	return asn1.Marshal(cert)
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
		signingKey = r.multiPQCKey
	} else if r.privateKey != nil {
		signingKey = r.privateKey
	} else {
		return nil, fmt.Errorf("no signing key available")
	}

	template.Issuer = r.certificate.Subject

	rsaSigner := &RSASignerWrapper{rsaKey: r.dummyRSAKey}

	rsaCertDER, err := x509.CreateCertificate(rand.Reader, template, r.certificate, &r.dummyRSAKey.PublicKey, rsaSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA certificate: %w", err)
	}

	pqCertDER, err := r.replaceCertificateSignatureWithPQ(rsaCertDER, signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to replace with PQ signature: %w", err)
	}

	return pqCertDER, nil
}

func (r *RootCA) SignWithMultiPQC(template *x509.Certificate, publicKey interface{}) ([]byte, error) {
	if !r.useMultiPQC || r.multiPQCKey == nil {
		return nil, fmt.Errorf("multi-PQC not available")
	}

	return r.SignCertificate(template, publicKey)
}

func (r *RootCA) IsValidIssuer(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	if r.certificate != nil {
		return cert.Issuer.String() == r.certificate.Subject.String()
	}

	return false
}

func (r *RootCA) GetKeyFingerprint() (string, error) {
	if r.certificate != nil {
		fingerprint := utils.HashPrefix(string(r.certificate.Raw), 16)
		return fingerprint, nil
	}

	return "", fmt.Errorf("no certificate available")
}

func (r *RootCA) ValidateIntegrity() error {
	if r.certificate == nil {
		return fmt.Errorf("root CA not initialized")
	}

	testMessage := []byte("integrity-test-message")

	if r.useMultiPQC && r.multiPQCKey != nil {
		signature, err := r.multiPQCKey.SignMessage(testMessage)
		if err != nil {
			return fmt.Errorf("failed to sign test data with multi-PQC: %w", err)
		}

		multiPQCPublic, err := r.multiPQCKey.GetPublicKey()
		if err != nil {
			return fmt.Errorf("failed to get multi-PQC public key: %w", err)
		}

		if !multiPQCPublic.Verify(testMessage, signature) {
			return fmt.Errorf("multi-PQC signature verification failed - key integrity compromised")
		}

		fmt.Println("✅ Multi-PQC integrity check passed")
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

		fmt.Println("✅ Single PQC integrity check passed")
	} else {
		return fmt.Errorf("no private key available for integrity check")
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