package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/utils"
)

type IntermediateCA struct {
	config      *utils.Config
	rootCA      *RootCA
	certificate *x509.Certificate
	privateKey  interface{}
}

func NewIntermediateCA(config *utils.Config, rootCA *RootCA) *IntermediateCA {
	return &IntermediateCA{
		config: config,
		rootCA: rootCA,
	}
}

func (i *IntermediateCA) Initialize() error {
	certPath := filepath.Join(i.config.KeysPath, "intermediate-ca.pem")
	keyPath := filepath.Join(i.config.KeysPath, "intermediate-ca-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return i.loadExisting(certPath, keyPath)
	}

	return i.generateNew(certPath, keyPath)
}

func (i *IntermediateCA) loadExisting(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read intermediate CA certificate: %v", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read intermediate CA private key: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode intermediate CA certificate")
	}

	i.certificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA certificate: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode intermediate CA private key")
	}

	i.privateKey, err = pq.ParsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA private key: %v", err)
	}

	return nil
}

func (i *IntermediateCA) generateNew(certPath, keyPath string) error {
	privateKey, err := pq.GenerateKey("dilithium3")
	if err != nil {
		return fmt.Errorf("failed to generate intermediate CA private key: %v", err)
	}

	publicKey, err := pq.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get public key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
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

	certDER, err := x509.CreateCertificate(rand.Reader, template, i.rootCA.GetCertificate(), publicKey, i.rootCA.GetPrivateKey())
	if err != nil {
		return fmt.Errorf("failed to create intermediate CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyDER, err := pq.MarshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write intermediate CA certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write intermediate CA private key: %v", err)
	}

	i.certificate, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	i.privateKey = privateKey

	return nil
}

func (i *IntermediateCA) GetCertificate() *x509.Certificate {
	return i.certificate
}

func (i *IntermediateCA) GetPrivateKey() interface{} {
	return i.privateKey
}

func (i *IntermediateCA) GetCertificatePEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: i.certificate.Raw,
	}), nil
}