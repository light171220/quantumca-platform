package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	multiPQCKey *pq.MultiPQCPrivateKey
	keyStore    *keymanager.EncryptedKeyStore
	useMultiPQC bool
	dummyRSAKey *rsa.PrivateKey
	Algorithms  []string
}

func NewIntermediateCA(config *utils.Config, rootCA *RootCA) *IntermediateCA {
	dummyKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &IntermediateCA{
		config:      config,
		rootCA:      rootCA,
		useMultiPQC: true,
		dummyRSAKey: dummyKey,
		Algorithms:  []string{},
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
	keyData, metadata, err := i.keyStore.LoadKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA private key: %w", err)
	}
	defer i.secureZero(keyData)

	if metadata.Algorithm == "multi-pqc" {
		i.multiPQCKey, err = pq.ParseMultiPQCPrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("failed to parse multi-PQC private key: %w", err)
		}
		i.useMultiPQC = true
		i.Algorithms = []string{
			"multi-pqc",
			i.multiPQCKey.PrimaryAlgorithm,
			i.multiPQCKey.SecondaryAlgorithm,
			i.multiPQCKey.TertiaryAlgorithm,
		}
	} else {
		i.privateKey, err = pq.ParsePrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("failed to parse intermediate CA private key: %w", err)
		}
		i.useMultiPQC = false
		i.Algorithms = []string{metadata.Algorithm}
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
	if i.useMultiPQC {
		return i.generateMultiPQCCA()
	}
	return i.generateSinglePQCCA()
}

func (i *IntermediateCA) generateMultiPQCCA() error {
	multiPQCKey, err := pq.GenerateMultiPQCKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate multi-PQC intermediate CA key: %w", err)
	}

	serialNumber, err := i.generateSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"QuantumCA Intermediate CA"},
			OrganizationalUnit: []string{"Multi-PQC Intermediate Authority"},
			CommonName:         "QuantumCA Multi-PQC Intermediate Certificate Authority",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := i.createSignedCertificateWithPQReplacement(template, multiPQCKey)
	if err != nil {
		return fmt.Errorf("failed to create multi-PQC intermediate CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	i.certificate = cert

	multiPQCPrivateKeyDER, err := pq.MarshalMultiPQCPrivateKey(multiPQCKey)
	if err != nil {
		return fmt.Errorf("failed to marshal multi-PQC private key: %w", err)
	}

	keyID := fmt.Sprintf("intermediate-ca-multi-pqc-%d", time.Now().Unix())
	if err := i.keyStore.StoreKey(keyID, multiPQCPrivateKeyDER, "intermediate-ca", "multi-pqc"); err != nil {
		return fmt.Errorf("failed to store multi-PQC private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := i.keyStore.StoreCertificate(keyID, certPEM); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	i.multiPQCKey = multiPQCKey
	i.useMultiPQC = true
	i.Algorithms = []string{
		"multi-pqc",
		multiPQCKey.PrimaryAlgorithm,
		multiPQCKey.SecondaryAlgorithm,
		multiPQCKey.TertiaryAlgorithm,
	}

	i.secureZero(multiPQCPrivateKeyDER)

	return nil
}

func (i *IntermediateCA) generateSinglePQCCA() error {
	privateKey, err := pq.GenerateKey("dilithium5")
	if err != nil {
		return fmt.Errorf("failed to generate intermediate CA private key: %w", err)
	}

	serialNumber, err := i.generateSerialNumber()
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

	certDER, err := i.createSignedCertificateWithPQReplacement(template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create intermediate CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	i.certificate = cert

	privateKeyDER, err := pq.MarshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyID := fmt.Sprintf("intermediate-ca-%d", time.Now().Unix())
	if err := i.keyStore.StoreKey(keyID, privateKeyDER, "intermediate-ca", "dilithium5"); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := i.keyStore.StoreCertificate(keyID, certPEM); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	i.privateKey = privateKey
	i.useMultiPQC = false
	i.Algorithms = []string{"dilithium5"}

	i.secureZero(privateKeyDER)

	return nil
}

func (i *IntermediateCA) createSignedCertificateWithPQReplacement(template *x509.Certificate, pqKey interface{}) ([]byte, error) {
	template.Issuer = i.rootCA.GetCertificate().Subject

	rsaSigner := &RSASignerWrapper{rsaKey: i.dummyRSAKey}
	
	rsaCertDER, err := x509.CreateCertificate(rand.Reader, template, i.rootCA.GetCertificate(), &i.dummyRSAKey.PublicKey, rsaSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA certificate: %w", err)
	}

	pqCertDER, err := i.replaceCertificateSignatureWithPQ(rsaCertDER, pqKey)
	if err != nil {
		return nil, fmt.Errorf("failed to replace with PQ signature: %w", err)
	}

	return pqCertDER, nil
}

func (i *IntermediateCA) replaceCertificateSignatureWithPQ(rsaCertDER []byte, pqKey interface{}) ([]byte, error) {
	var cert struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}

	_, err := asn1.Unmarshal(rsaCertDER, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
	}

	var signingKey interface{}
	if i.rootCA.IsMultiPQC() {
		signingKey = i.rootCA.GetPrivateKey()
	} else {
		signingKey = i.rootCA.GetPrivateKey()
	}

	pqSignature, err := pq.Sign(signingKey, cert.TBSCertificate.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create PQ signature: %w", err)
	}

	cert.SignatureValue = asn1.BitString{
		Bytes:     pqSignature,
		BitLength: len(pqSignature) * 8,
	}

	return asn1.Marshal(cert)
}

func (i *IntermediateCA) generateSerialNumber() (*big.Int, error) {
	serialBytes := make([]byte, 20)
	if _, err := rand.Read(serialBytes); err != nil {
		serialNumber := big.NewInt(time.Now().Unix())
		return serialNumber, nil
	}
	
	serialBytes[0] &= 0x7F
	serial := new(big.Int).SetBytes(serialBytes)
	
	if serial.Sign() <= 0 {
		return big.NewInt(time.Now().Unix()), nil
	}
	
	return serial, nil
}

func (i *IntermediateCA) GetCertificate() *x509.Certificate {
	return i.certificate
}

func (i *IntermediateCA) GetPrivateKey() interface{} {
	if i.useMultiPQC {
		return i.multiPQCKey
	}
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

	if i.certificate == nil {
		return nil, fmt.Errorf("intermediate CA not properly initialized")
	}

	var signingKey interface{}
	if i.useMultiPQC && i.multiPQCKey != nil {
		signingKey = i.multiPQCKey
	} else if i.privateKey != nil {
		signingKey = i.privateKey
	} else {
		return nil, fmt.Errorf("no signing key available")
	}

	template.Issuer = i.certificate.Subject

	rsaSigner := &RSASignerWrapper{rsaKey: i.dummyRSAKey}

	rsaCertDER, err := x509.CreateCertificate(rand.Reader, template, i.certificate, &i.dummyRSAKey.PublicKey, rsaSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA certificate: %w", err)
	}

	pqCertDER, err := i.replaceCertificateSignatureWithPQForEndEntity(rsaCertDER, signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to replace with PQ signature: %w", err)
	}

	return pqCertDER, nil
}

func (i *IntermediateCA) replaceCertificateSignatureWithPQForEndEntity(rsaCertDER []byte, pqKey interface{}) ([]byte, error) {
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
	if i.certificate == nil {
		return fmt.Errorf("intermediate CA not initialized")
	}

	testData := []byte("integrity-test-message")

	if i.useMultiPQC && i.multiPQCKey != nil {
		signature, err := i.multiPQCKey.SignMessage(testData)
		if err != nil {
			return fmt.Errorf("failed to sign test data with multi-PQC: %w", err)
		}

		multiPQCPublic, err := i.multiPQCKey.GetPublicKey()
		if err != nil {
			return fmt.Errorf("failed to get multi-PQC public key: %w", err)
		}

		if !multiPQCPublic.Verify(testData, signature) {
			return fmt.Errorf("multi-PQC signature verification failed - key integrity compromised")
		}

		fmt.Println("✅ Multi-PQC integrity check passed")
	} else if i.privateKey != nil {
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

		fmt.Println("✅ Single PQC integrity check passed")
	} else {
		return fmt.Errorf("no private key available for integrity check")
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
		for j := range data {
			data[j] = 0
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
		"algorithms":    i.Algorithms,
		"multi_pqc":     i.useMultiPQC,
	}
}

func (i *IntermediateCA) IsMultiPQC() bool {
	return i.useMultiPQC
}