package handlers

import (
	"crypto/x509"
	"net/http"

	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/utils"

	"github.com/gin-gonic/gin"
)

type CAInfoHandler struct {
	config *utils.Config
	logger *utils.Logger
	issuer *ca.Issuer
}

func NewCAInfoHandler(config *utils.Config, logger *utils.Logger) *CAInfoHandler {
	return &CAInfoHandler{
		config: config,
		logger: logger,
		issuer: ca.NewIssuer(config),
	}
}

type CASubject struct {
	CommonName         string   `json:"common_name"`
	Country            []string `json:"country"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Locality           []string `json:"locality"`
	Province           []string `json:"province"`
}

type RootCAResponse struct {
	Certificate       string            `json:"certificate"`
	SerialNumber      string            `json:"serial_number"`
	Subject           CASubject         `json:"subject"`
	NotBefore         string            `json:"not_before"`
	NotAfter          string            `json:"not_after"`
	Fingerprint       string            `json:"fingerprint"`
	KeyUsages         []string          `json:"key_usages"`
	BasicConstraints  BasicConstraints  `json:"basic_constraints"`
	Algorithms        []string          `json:"algorithms"`
	IsMultiPQC        bool              `json:"is_multi_pqc"`
}

type IntermediateCAInfoResponse struct {
	Certificate       string            `json:"certificate"`
	SerialNumber      string            `json:"serial_number"`
	Subject           CASubject         `json:"subject"`
	Issuer            CASubject         `json:"issuer"`
	NotBefore         string            `json:"not_before"`
	NotAfter          string            `json:"not_after"`
	Fingerprint       string            `json:"fingerprint"`
	KeyUsages         []string          `json:"key_usages"`
	BasicConstraints  BasicConstraints  `json:"basic_constraints"`
	Algorithms        []string          `json:"algorithms"`
	IsMultiPQC        bool              `json:"is_multi_pqc"`
}

type BasicConstraints struct {
	IsCA       bool `json:"is_ca"`
	MaxPathLen int  `json:"max_path_len"`
}

type AlgorithmsResponse struct {
	Signature []AlgorithmInfo `json:"signature"`
	KEM       []AlgorithmInfo `json:"kem"`
	MultiPQC  bool            `json:"multi_pqc_supported"`
}

type AlgorithmInfo struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	SecurityBits int    `json:"security_bits"`
	Type         string `json:"type"`
}

func (h *CAInfoHandler) GetRootCAInfo(c *gin.Context) {
	rootCA := ca.NewRootCA(h.config)
	err := rootCA.Initialize()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Root CA not available"})
		return
	}

	cert := rootCA.GetCertificate()
	if cert == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Root CA certificate not available"})
		return
	}

	certPEM, err := rootCA.GetCertificatePEM()
	if err != nil {
		h.logger.LogError(err, "Failed to get root CA certificate PEM", nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate"})
		return
	}

	fingerprint, err := rootCA.GetKeyFingerprint()
	if err != nil {
		fingerprint = "unknown"
	}

	certInfo := rootCA.GetCertificateInfo()
	algorithms, _ := certInfo["algorithms"].([]string)
	isMultiPQC, _ := certInfo["multi_pqc"].(bool)

	response := &RootCAResponse{
		Certificate:  string(certPEM),
		SerialNumber: cert.SerialNumber.String(),
		Subject: CASubject{
			CommonName:         cert.Subject.CommonName,
			Country:            cert.Subject.Country,
			Organization:       cert.Subject.Organization,
			OrganizationalUnit: cert.Subject.OrganizationalUnit,
			Locality:           cert.Subject.Locality,
			Province:           cert.Subject.Province,
		},
		NotBefore:   cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:    cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Fingerprint: fingerprint,
		KeyUsages:   h.parseKeyUsages(cert.KeyUsage),
		BasicConstraints: BasicConstraints{
			IsCA:       cert.IsCA,
			MaxPathLen: cert.MaxPathLen,
		},
		Algorithms: algorithms,
		IsMultiPQC: isMultiPQC,
	}

	c.JSON(http.StatusOK, response)
}

func (h *CAInfoHandler) GetIntermediateCAInfo(c *gin.Context) {
	rootCA := ca.NewRootCA(h.config)
	err := rootCA.Initialize()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Root CA not available"})
		return
	}

	intermediateCA := ca.NewIntermediateCA(h.config, rootCA)
	err = intermediateCA.Initialize()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Intermediate CA not available"})
		return
	}

	cert := intermediateCA.GetCertificate()
	if cert == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Intermediate CA certificate not available"})
		return
	}

	certPEM, err := intermediateCA.GetCertificatePEM()
	if err != nil {
		h.logger.LogError(err, "Failed to get intermediate CA certificate PEM", nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate"})
		return
	}

	fingerprint, err := intermediateCA.GetKeyFingerprint()
	if err != nil {
		fingerprint = "unknown"
	}

	certInfo := intermediateCA.GetCertificateInfo()
	algorithms, _ := certInfo["algorithms"].([]string)
	isMultiPQC, _ := certInfo["multi_pqc"].(bool)

	response := &IntermediateCAInfoResponse{
		Certificate:  string(certPEM),
		SerialNumber: cert.SerialNumber.String(),
		Subject: CASubject{
			CommonName:         cert.Subject.CommonName,
			Country:            cert.Subject.Country,
			Organization:       cert.Subject.Organization,
			OrganizationalUnit: cert.Subject.OrganizationalUnit,
			Locality:           cert.Subject.Locality,
			Province:           cert.Subject.Province,
		},
		Issuer: CASubject{
			CommonName:         cert.Issuer.CommonName,
			Country:            cert.Issuer.Country,
			Organization:       cert.Issuer.Organization,
			OrganizationalUnit: cert.Issuer.OrganizationalUnit,
			Locality:           cert.Issuer.Locality,
			Province:           cert.Issuer.Province,
		},
		NotBefore:   cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:    cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Fingerprint: fingerprint,
		KeyUsages:   h.parseKeyUsages(cert.KeyUsage),
		BasicConstraints: BasicConstraints{
			IsCA:       cert.IsCA,
			MaxPathLen: cert.MaxPathLen,
		},
		Algorithms: algorithms,
		IsMultiPQC: isMultiPQC,
	}

	c.JSON(http.StatusOK, response)
}

func (h *CAInfoHandler) GetCertificateChain(c *gin.Context) {
	rootCA := ca.NewRootCA(h.config)
	err := rootCA.Initialize()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Root CA not available"})
		return
	}

	rootCertPEM, err := rootCA.GetCertificatePEM()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get root certificate"})
		return
	}

	chain := []string{}
	
	intermediateCA := ca.NewIntermediateCA(h.config, rootCA)
	err = intermediateCA.Initialize()
	if err == nil {
		intermediateCertPEM, err := intermediateCA.GetCertificatePEM()
		if err == nil {
			chain = append(chain, string(intermediateCertPEM))
		}
	}

	response := &CertificateChainResponse{
		Chain: chain,
		Root:  string(rootCertPEM),
	}

	c.JSON(http.StatusOK, response)
}

func (h *CAInfoHandler) GetSupportedAlgorithms(c *gin.Context) {
	signatureAlgorithms := []AlgorithmInfo{
		{
			Name:         "dilithium2",
			Description:  "CRYSTALS-Dilithium with NIST Level 1 security",
			SecurityBits: 128,
			Type:         "signature",
		},
		{
			Name:         "dilithium3",
			Description:  "CRYSTALS-Dilithium with NIST Level 3 security",
			SecurityBits: 192,
			Type:         "signature",
		},
		{
			Name:         "dilithium5",
			Description:  "CRYSTALS-Dilithium with NIST Level 5 security",
			SecurityBits: 256,
			Type:         "signature",
		},
		{
			Name:         "sphincs-sha256-128f",
			Description:  "SPHINCS+ SHA-256 128-bit fast variant",
			SecurityBits: 128,
			Type:         "signature",
		},
		{
			Name:         "sphincs-sha256-128s",
			Description:  "SPHINCS+ SHA-256 128-bit small variant",
			SecurityBits: 128,
			Type:         "signature",
		},
		{
			Name:         "sphincs-sha256-192f",
			Description:  "SPHINCS+ SHA-256 192-bit fast variant",
			SecurityBits: 192,
			Type:         "signature",
		},
		{
			Name:         "sphincs-sha256-256f",
			Description:  "SPHINCS+ SHA-256 256-bit fast variant",
			SecurityBits: 256,
			Type:         "signature",
		},
	}

	kemAlgorithms := []AlgorithmInfo{
		{
			Name:         "kyber512",
			Description:  "CRYSTALS-Kyber with NIST Level 1 security",
			SecurityBits: 128,
			Type:         "kem",
		},
		{
			Name:         "kyber768",
			Description:  "CRYSTALS-Kyber with NIST Level 3 security",
			SecurityBits: 192,
			Type:         "kem",
		},
		{
			Name:         "kyber1024",
			Description:  "CRYSTALS-Kyber with NIST Level 5 security",
			SecurityBits: 256,
			Type:         "kem",
		},
	}

	response := &AlgorithmsResponse{
		Signature: signatureAlgorithms,
		KEM:       kemAlgorithms,
		MultiPQC:  true,
	}

	c.JSON(http.StatusOK, response)
}

func (h *CAInfoHandler) parseKeyUsages(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "digital_signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "content_commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "key_encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "data_encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "key_agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "cert_sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "crl_sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "encipher_only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "decipher_only")
	}

	return usages
}