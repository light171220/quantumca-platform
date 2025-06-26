package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"software.sslmate.com/src/go-pkcs12"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type ExportHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewExportHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *ExportHandler {
	return &ExportHandler{
		db:     db,
		config: config,
		logger: logger,
	}
}

type ExportFormatsRequest struct {
	Formats []string `json:"formats" binding:"required"`
}

type CertificateChainResponse struct {
	Certificate   string   `json:"certificate"`
	PrivateKey    string   `json:"private_key,omitempty"`
	Chain         []string `json:"chain"`
	Root          string   `json:"root"`
}

func (h *ExportHandler) GetCertificateChain(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	cert, err := storage.GetCertificateWithContext(ctx, h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate"})
		return
	}

	if cert.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	chain, err := h.buildCertificateChain(ctx)
	if err != nil {
		h.logger.LogError(err, "Failed to build certificate chain", map[string]interface{}{
			"certificate_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build certificate chain"})
		return
	}

	includePrivateKey := c.Query("include_private_key") == "true"

	response := &CertificateChainResponse{
		Certificate: cert.CertificatePEM,
		Chain:       chain.Intermediates,
		Root:        chain.Root,
	}

	if includePrivateKey {
		response.PrivateKey = cert.PrivateKeyPEM
	}

	c.JSON(http.StatusOK, response)
}

func (h *ExportHandler) ExportPKCS12(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	password := c.Query("password")
	if password == "" {
		var genErr error
		password, genErr = utils.GenerateRandomString(16)
		if genErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate password"})
			return
		}
	}

	cert, err := storage.GetCertificateWithContext(ctx, h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate"})
		return
	}

	if cert.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	pkcs12Data, err := h.createPKCS12(cert, password)
	if err != nil {
		h.logger.LogError(err, "Failed to create PKCS12", map[string]interface{}{
			"certificate_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create PKCS12"})
		return
	}

	filename := utils.SanitizeFilename(strings.ReplaceAll(cert.CommonName, "*", "wildcard"))
	
	c.Header("Content-Type", "application/x-pkcs12")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.p12", filename))
	c.Header("X-PKCS12-Password", password)
	
	c.Data(http.StatusOK, "application/x-pkcs12", pkcs12Data)
}

func (h *ExportHandler) ExportMultipleFormats(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	var req ExportFormatsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	cert, err := storage.GetCertificateWithContext(ctx, h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate"})
		return
	}

	if cert.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	zipBuffer := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuffer)

	filename := utils.SanitizeFilename(strings.ReplaceAll(cert.CommonName, "*", "wildcard"))

	for _, format := range req.Formats {
		switch format {
		case "pem":
			if err := h.addPEMToZip(zipWriter, cert, filename); err != nil {
				h.logger.LogError(err, "Failed to add PEM to zip", nil)
				continue
			}
		case "der":
			if err := h.addDERToZip(zipWriter, cert, filename); err != nil {
				h.logger.LogError(err, "Failed to add DER to zip", nil)
				continue
			}
		case "p7b":
			if err := h.addP7BToZip(zipWriter, cert, filename); err != nil {
				h.logger.LogError(err, "Failed to add P7B to zip", nil)
				continue
			}
		case "bundle":
			if err := h.addBundleToZip(zipWriter, cert, filename); err != nil {
				h.logger.LogError(err, "Failed to add bundle to zip", nil)
				continue
			}
		case "json":
			if err := h.addJSONToZip(zipWriter, cert, filename); err != nil {
				h.logger.LogError(err, "Failed to add JSON to zip", nil)
				continue
			}
		}
	}

	zipWriter.Close()

	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s-export.zip", filename))
	
	c.Data(http.StatusOK, "application/zip", zipBuffer.Bytes())
}

func (h *ExportHandler) buildCertificateChain(ctx context.Context) (*struct {
	Intermediates []string
	Root          string
}, error) {
	rootCA := ca.NewRootCA(h.config)
	err := rootCA.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize root CA: %w", err)
	}

	rootCertPEM, err := rootCA.GetCertificatePEM()
	if err != nil {
		return nil, fmt.Errorf("failed to get root certificate: %w", err)
	}

	chain := &struct {
		Intermediates []string
		Root          string
	}{
		Intermediates: []string{},
		Root:          string(rootCertPEM),
	}

	intermediateCA := ca.NewIntermediateCA(h.config, rootCA)
	err = intermediateCA.Initialize()
	if err == nil {
		intermediateCertPEM, err := intermediateCA.GetCertificatePEM()
		if err == nil {
			chain.Intermediates = append(chain.Intermediates, string(intermediateCertPEM))
		}
	}

	return chain, nil
}

func (h *ExportHandler) createPKCS12(cert *storage.Certificate, password string) ([]byte, error) {
	certBlock, _ := pem.Decode([]byte(cert.CertificatePEM))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(cert.PrivateKeyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}

	// Parse the private key from PEM
	privKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	pfxData, err := pkcs12.Encode(rand.Reader, privKey, x509Cert, nil, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS12: %w", err)
	}

	return pfxData, nil
}

func (h *ExportHandler) addPEMToZip(zipWriter *zip.Writer, cert *storage.Certificate, filename string) error {
	certFile, err := zipWriter.Create(fmt.Sprintf("%s.crt", filename))
	if err != nil {
		return err
	}
	_, err = certFile.Write([]byte(cert.CertificatePEM))
	if err != nil {
		return err
	}

	keyFile, err := zipWriter.Create(fmt.Sprintf("%s.key", filename))
	if err != nil {
		return err
	}
	_, err = keyFile.Write([]byte(cert.PrivateKeyPEM))
	return err
}

func (h *ExportHandler) addDERToZip(zipWriter *zip.Writer, cert *storage.Certificate, filename string) error {
	certBlock, _ := pem.Decode([]byte(cert.CertificatePEM))
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	derFile, err := zipWriter.Create(fmt.Sprintf("%s.der", filename))
	if err != nil {
		return err
	}
	_, err = derFile.Write(certBlock.Bytes)
	return err
}

func (h *ExportHandler) addP7BToZip(zipWriter *zip.Writer, cert *storage.Certificate, filename string) error {
	certBlock, _ := pem.Decode([]byte(cert.CertificatePEM))
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	chain, err := h.buildCertificateChain(context.Background())
	if err != nil {
		chain = &struct {
			Intermediates []string
			Root          string
		}{
			Intermediates: []string{},
			Root:          "",
		}
	}

	var certs []*x509.Certificate
	certs = append(certs, x509Cert)

	for _, intermediatePEM := range chain.Intermediates {
		block, _ := pem.Decode([]byte(intermediatePEM))
		if block != nil {
			intermediateCert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, intermediateCert)
			}
		}
	}

	if chain.Root != "" {
		block, _ := pem.Decode([]byte(chain.Root))
		if block != nil {
			rootCert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, rootCert)
			}
		}
	}

	p7bFile, err := zipWriter.Create(fmt.Sprintf("%s.p7b", filename))
	if err != nil {
		return err
	}

	p7bData := "-----BEGIN PKCS7-----\n"
	for _, c := range certs {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})
		p7bData += string(certPEM)
	}
	p7bData += "-----END PKCS7-----\n"

	_, err = p7bFile.Write([]byte(p7bData))
	return err
}

func (h *ExportHandler) addBundleToZip(zipWriter *zip.Writer, cert *storage.Certificate, filename string) error {
	bundleFile, err := zipWriter.Create(fmt.Sprintf("%s-bundle.pem", filename))
	if err != nil {
		return err
	}
	
	bundle := cert.CertificatePEM + "\n" + cert.PrivateKeyPEM
	_, err = bundleFile.Write([]byte(bundle))
	return err
}

func (h *ExportHandler) addJSONToZip(zipWriter *zip.Writer, cert *storage.Certificate, filename string) error {
	jsonFile, err := zipWriter.Create(fmt.Sprintf("%s.json", filename))
	if err != nil {
		return err
	}

	certData := map[string]interface{}{
		"id":                    cert.ID,
		"serial_number":         cert.SerialNumber,
		"common_name":           cert.CommonName,
		"subject_alt_names":     cert.SubjectAltNames,
		"certificate_pem":       cert.CertificatePEM,
		"private_key_pem":       cert.PrivateKeyPEM,
		"algorithms":            cert.Algorithms,
		"is_multi_pqc":         cert.IsMultiPQC,
		"has_kem":              cert.HasKEM,
		"multi_pqc_certificates": cert.MultiPQCCertificates,
		"multi_pqc_private_keys": cert.MultiPQCPrivateKeys,
		"kem_public_key_pem":   cert.KEMPublicKeyPEM,
		"kem_private_key_pem":  cert.KEMPrivateKeyPEM,
		"fingerprint":          cert.Fingerprint,
		"key_id":               cert.KeyID,
		"not_before":           cert.NotBefore.Format(time.RFC3339),
		"not_after":            cert.NotAfter.Format(time.RFC3339),
		"status":               cert.Status,
		"created_at":           cert.CreatedAt.Format(time.RFC3339),
		"updated_at":           cert.UpdatedAt.Format(time.RFC3339),
	}

	jsonData := storage.MarshalJSON(certData)

	_, err = jsonFile.Write([]byte(jsonData))
	return err
}