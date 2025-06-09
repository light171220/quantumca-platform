package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

type CertificateTemplate struct {
	Type         string
	Subject      pkix.Name
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	ValidityDays int
	IsCA         bool
	MaxPathLen   int
}

func GetCertificateTemplates() map[string]*CertificateTemplate {
	return map[string]*CertificateTemplate{
		"tls-server": {
			Type: "TLS Server Certificate",
			Subject: pkix.Name{
				Organization:       []string{"QuantumCA"},
				OrganizationalUnit: []string{"TLS Server Certificate"},
			},
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			ValidityDays: 365,
			IsCA:         false,
		},
		"tls-client": {
			Type: "TLS Client Certificate",
			Subject: pkix.Name{
				Organization:       []string{"QuantumCA"},
				OrganizationalUnit: []string{"TLS Client Certificate"},
			},
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			ValidityDays: 365,
			IsCA:         false,
		},
		"intermediate-ca": {
			Type: "Intermediate CA Certificate",
			Subject: pkix.Name{
				Organization:       []string{"QuantumCA"},
				OrganizationalUnit: []string{"Intermediate CA"},
			},
			KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{},
			ValidityDays: 1825,
			IsCA:         true,
			MaxPathLen:   0,
		},
		"code-signing": {
			Type: "Code Signing Certificate",
			Subject: pkix.Name{
				Organization:       []string{"QuantumCA"},
				OrganizationalUnit: []string{"Code Signing Certificate"},
			},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			ValidityDays: 1095,
			IsCA:         false,
		},
		"email": {
			Type: "Email Certificate",
			Subject: pkix.Name{
				Organization:       []string{"QuantumCA"},
				OrganizationalUnit: []string{"Email Certificate"},
			},
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			ValidityDays: 365,
			IsCA:         false,
		},
	}
}

func ApplyTemplate(template *x509.Certificate, templateName string, subject pkix.Name) {
	templates := GetCertificateTemplates()
	certTemplate, exists := templates[templateName]
	if !exists {
		certTemplate = templates["tls-server"]
	}

	template.KeyUsage = certTemplate.KeyUsage
	template.ExtKeyUsage = certTemplate.ExtKeyUsage
	template.BasicConstraintsValid = true
	template.IsCA = certTemplate.IsCA
	
	if certTemplate.IsCA {
		template.MaxPathLen = certTemplate.MaxPathLen
		template.MaxPathLenZero = certTemplate.MaxPathLen == 0
	}

	template.NotBefore = time.Now()
	template.NotAfter = time.Now().AddDate(0, 0, certTemplate.ValidityDays)

	if subject.CommonName != "" {
		template.Subject = subject
	} else {
		template.Subject = certTemplate.Subject
	}
}