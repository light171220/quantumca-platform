package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

type CertificateBuilder struct {
	template *x509.Certificate
}

func NewCertificateBuilder() *CertificateBuilder {
	return &CertificateBuilder{
		template: &x509.Certificate{},
	}
}

func (b *CertificateBuilder) SetSubject(subject pkix.Name) *CertificateBuilder {
	b.template.Subject = subject
	return b
}

func (b *CertificateBuilder) SetSerialNumber(serialNumber int64) *CertificateBuilder {
	b.template.SerialNumber = big.NewInt(serialNumber)
	return b
}

func (b *CertificateBuilder) SetValidity(notBefore, notAfter time.Time) *CertificateBuilder {
	b.template.NotBefore = notBefore
	b.template.NotAfter = notAfter
	return b
}

func (b *CertificateBuilder) SetKeyUsage(usage x509.KeyUsage) *CertificateBuilder {
	b.template.KeyUsage = usage
	return b
}

func (b *CertificateBuilder) SetExtKeyUsage(usage []x509.ExtKeyUsage) *CertificateBuilder {
	b.template.ExtKeyUsage = usage
	return b
}

func (b *CertificateBuilder) SetBasicConstraints(isCA bool, maxPathLen int) *CertificateBuilder {
	b.template.BasicConstraintsValid = true
	b.template.IsCA = isCA
	if maxPathLen >= 0 {
		b.template.MaxPathLen = maxPathLen
		b.template.MaxPathLenZero = maxPathLen == 0
	}
	return b
}

func (b *CertificateBuilder) SetDNSNames(names []string) *CertificateBuilder {
	b.template.DNSNames = names
	return b
}

func (b *CertificateBuilder) SetIPAddresses(ips []net.IP) *CertificateBuilder {
	b.template.IPAddresses = ips
	return b
}

func (b *CertificateBuilder) Build() *x509.Certificate {
	return b.template
}