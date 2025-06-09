package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"quantumca-platform/internal/crypto/pq"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type Issuer struct {
	config        *utils.Config
	rootCA        *RootCA
	intermediateCA *IntermediateCA
}

type CertificateRequest struct {
	CommonName      string
	SubjectAltNames []string
	ValidityDays    int
	Customer        *storage.Customer
}

type CertificateResponse struct {
	SerialNumber   string
	CertificatePEM string
	PrivateKeyPEM  string
	Algorithms     []string
	NotBefore      time.Time
	NotAfter       time.Time
}

type IntermediateCARequest struct {
	CommonName string
	Country    string
	State      string
	City       string
	Org        string
	OrgUnit    string
	Customer   *storage.Customer
}

func NewIssuer(config *utils.Config) *Issuer {
	rootCA := NewRootCA(config)
	intermediateCA := NewIntermediateCA(config, rootCA)
	
	rootCA.Initialize()
	intermediateCA.Initialize()

	return &Issuer{
		config:        config,
		rootCA:        rootCA,
		intermediateCA: intermediateCA,
	}
}

func (i *Issuer) IssueCertificate(req *CertificateRequest) (*CertificateResponse, error) {
	privateKey, err := pq.GenerateKey("dilithium2")
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey, err := pq.GetPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	subject := pkix.Name{
		CommonName:         req.CommonName,
		Organization:       []string{req.Customer.CompanyName},
		OrganizationalUnit: []string{"QuantumCA Certificate"},
		Country:            []string{"US"},
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, req.ValidityDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, san := range req.SubjectAltNames {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, i.intermediateCA.GetCertificate(), publicKey, i.intermediateCA.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyDER, err := pq.MarshalPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return &CertificateResponse{
		SerialNumber:   serialNumber.String(),
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		Algorithms:     []string{"dilithium2"},
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
	}, nil
}

func (i *Issuer) IssueIntermediateCA(req *IntermediateCARequest) (*CertificateResponse, error) {
	privateKey, err := pq.GenerateKey("dilithium3")
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey, err := pq.GetPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	subject := pkix.Name{
		CommonName:         req.CommonName,
		Country:            []string{req.Country},
		Province:           []string{req.State},
		Locality:           []string{req.City},
		Organization:       []string{req.Org},
		OrganizationalUnit: []string{req.OrgUnit},
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, i.rootCA.GetCertificate(), publicKey, i.rootCA.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyDER, err := pq.MarshalPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return &CertificateResponse{
		SerialNumber:   serialNumber.String(),
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		Algorithms:     []string{"dilithium3"},
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
	}, nil
}