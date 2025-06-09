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

type RootCA struct {
	config      *utils.Config
	certificate *x509.Certificate
	privateKey  interface{}
}

func NewRootCA(config *utils.Config) *RootCA {
	return &RootCA{
		config: config,
	}
}

func (r *RootCA) Initialize() error {
	certPath := filepath.Join(r.config.KeysPath, "root-ca.pem")
	keyPath := filepath.Join(r.config.KeysPath, "root-ca-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return r.loadExisting(certPath, keyPath)
	}

	return r.generateNew(certPath, keyPath)
}

func (r *RootCA) loadExisting(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read root CA certificate: %v", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read root CA private key: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode root CA certificate")
	}

	r.certificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA certificate: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode root CA private key")
	}

	r.privateKey, err = pq.ParsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA private key: %v", err)
	}

	return nil
}

func (r *RootCA) generateNew(certPath, keyPath string) error {
	privateKey, err := pq.GenerateKey("dilithium5")
	if err != nil {
		return fmt.Errorf("failed to generate root CA private key: %v", err)
	}

	publicKey, err := pq.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get public key: %v", err)
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
		return fmt.Errorf("failed to create root CA certificate: %v", err)
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
		return fmt.Errorf("failed to write root CA certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write root CA private key: %v", err)
	}

	r.certificate, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	r.privateKey = privateKey

	return nil
}

func (r *RootCA) GetCertificate() *x509.Certificate {
	return r.certificate
}

func (r *RootCA) GetPrivateKey() interface{} {
	return r.privateKey
}

func (r *RootCA) GetCertificatePEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: r.certificate.Raw,
	}), nil
}