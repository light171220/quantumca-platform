package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"time"
)

type ExtensionASN1 struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type AlgorithmIdentifierASN1 struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type SubjectPublicKeyInfoASN1 struct {
	Algorithm        AlgorithmIdentifierASN1
	SubjectPublicKey asn1.BitString
}

type ValidityASN1 struct {
	NotBefore time.Time `asn1:"utc"`
	NotAfter  time.Time `asn1:"utc"`
}

type RelativeDistinguishedNameASN1 struct {
	Type  asn1.ObjectIdentifier
	Value string `asn1:"utf8"`
}

type NameASN1 struct {
	RDNSequence []RelativeDistinguishedNameASN1 `asn1:"sequence"`
}

type TBSCertificateASN1 struct {
	Version              int                      `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber         *big.Int
	Signature            AlgorithmIdentifierASN1
	Issuer               NameASN1
	Validity             ValidityASN1
	Subject              NameASN1
	SubjectPublicKeyInfo SubjectPublicKeyInfoASN1
	IssuerUniqueID       asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueID      asn1.BitString `asn1:"optional,tag:2"`
	Extensions           []ExtensionASN1 `asn1:"optional,explicit,tag:3"`
}

type PQCertificateASN1 struct {
	TBSCertificate     TBSCertificateASN1
	SignatureAlgorithm AlgorithmIdentifierASN1
	SignatureValue     asn1.BitString
}

type BasicConstraintsASN1 struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional"`
}

type SubjectAltNameASN1 struct {
	DNSName      string `asn1:"optional,tag:2"`
	EmailAddress string `asn1:"optional,tag:1"`
	IPAddress    net.IP `asn1:"optional,tag:7"`
}

type PQAuthorityKeyIdentifier struct {
	KeyIdentifier             []byte                `asn1:"optional,tag:0"`
	AuthorityCertIssuer       []GeneralName         `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber *big.Int              `asn1:"optional,tag:2"`
}

type GeneralName struct {
	DNSName string `asn1:"optional,tag:2"`
	URI     string `asn1:"optional,tag:6"`
}

type PQGeneralName struct {
	URI string `asn1:"optional,tag:6"`
}

type PQCRLDistributionPoint struct {
	DistributionPoint asn1.ObjectIdentifier
}

type PQCertificateInfo struct {
	Version            int
	SerialNumber       *big.Int
	Subject            pkix.Name
	Issuer             pkix.Name
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	PublicKey          []byte
	Signature          []byte
	Extensions         map[string]interface{}
	Raw                TBSCertificateASN1
}

type PQCertificateChain struct {
	EndEntity     *PQCertificateInfo
	Intermediates []*PQCertificateInfo
	Root          *PQCertificateInfo
}