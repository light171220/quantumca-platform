package handlers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"

	"github.com/gin-gonic/gin"
)

type CRLHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewCRLHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *CRLHandler {
	return &CRLHandler{
		db:     db,
		config: config,
		logger: logger,
	}
}

type CRLInfoResponse struct {
	Version      int    `json:"version"`
	Issuer       string `json:"issuer"`
	ThisUpdate   string `json:"this_update"`
	NextUpdate   string `json:"next_update"`
	CRLNumber    int64  `json:"crl_number"`
	EntryCount   int    `json:"entry_count"`
	Size         int    `json:"size_bytes"`
	Algorithm    string `json:"signature_algorithm"`
	DownloadURL  string `json:"download_url"`
}

type GenerateCRLRequest struct {
	Force bool `json:"force"`
}

type GenerateCRLResponse struct {
	Success     bool   `json:"success"`
	CRLNumber   int64  `json:"crl_number"`
	EntryCount  int    `json:"entry_count"`
	Size        int    `json:"size_bytes"`
	GeneratedAt string `json:"generated_at"`
}

func (h *CRLHandler) DownloadCRL(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	crlData, err := h.generateCurrentCRL(ctx)
	if err != nil {
		h.logger.LogError(err, "Failed to generate current CRL", nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get CRL"})
		return
	}

	if len(crlData) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "CRL not available"})
		return
	}

	c.Header("Content-Type", "application/pkix-crl")
	c.Header("Content-Disposition", "attachment; filename=quantumca.crl")
	c.Header("Cache-Control", "public, max-age=3600")
	
	c.Data(http.StatusOK, "application/pkix-crl", crlData)
}

func (h *CRLHandler) GenerateCRL(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	var req GenerateCRLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Force = false
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

	tier, exists := c.Get("tier")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "Tier information required"})
		return
	}

	userTier, ok := tier.(int)
	if !ok || userTier < 2 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	result, err := h.generateCRL(ctx, req.Force)
	if err != nil {
		h.logger.LogError(err, "Failed to generate CRL", map[string]interface{}{
			"customer_id": custID,
			"force":       req.Force,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CRL"})
		return
	}

	h.logger.LogCertificateEvent("crl_generated", "", custID, map[string]interface{}{
		"crl_number":   result.CRLNumber,
		"entry_count":  result.EntryCount,
		"force":        req.Force,
	})

	response := &GenerateCRLResponse{
		Success:     true,
		CRLNumber:   result.CRLNumber,
		EntryCount:  result.EntryCount,
		Size:        result.Size,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *CRLHandler) generateCurrentCRL(ctx context.Context) ([]byte, error) {
	rootCA := ca.NewRootCA(h.config)
	err := rootCA.Initialize()
	if err != nil {
		return nil, err
	}

	intermediateCA := ca.NewIntermediateCA(h.config, rootCA)
	err = intermediateCA.Initialize()
	if err != nil {
		return nil, err
	}

	revokedCerts, err := h.getRevokedCertificates(ctx)
	if err != nil {
		return nil, err
	}

	var revokedCertList []pkix.RevokedCertificate
	for _, cert := range revokedCerts {
		serialNumber := new(big.Int)
		serialNumber.SetString(cert.SerialNumber, 10)
		
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: *cert.RevokedAt,
		}
		
		revokedCertList = append(revokedCertList, revokedCert)
	}

	now := time.Now()
	nextUpdate := now.Add(24 * time.Hour)
	
	crlNumber := now.Unix()
	crlNumberBytes, _ := asn1.Marshal(crlNumber)
	
	template := &x509.RevocationList{
		RevokedCertificates: revokedCertList,
		Number:              big.NewInt(crlNumber),
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 20},
				Value: crlNumberBytes,
			},
		},
	}

	issuerCert := intermediateCA.GetCertificate()
	issuerKey := intermediateCA.GetPrivateKey()

	signer, ok := issuerKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("issuer private key does not implement crypto.Signer")
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuerCert, signer)
	if err != nil {
		return nil, err
	}

	return crlBytes, nil
}

func (h *CRLHandler) generateCRL(ctx context.Context, force bool) (*struct {
	CRLNumber  int64
	EntryCount int
	Size       int
}, error) {
	crlData, err := h.generateCurrentCRL(ctx)
	if err != nil {
		return nil, err
	}

	entryCount, err := h.countRevokedCertificates(ctx)
	if err != nil {
		entryCount = 0
	}

	return &struct {
		CRLNumber  int64
		EntryCount int
		Size       int
	}{
		CRLNumber:  time.Now().Unix(),
		EntryCount: entryCount,
		Size:       len(crlData),
	}, nil
}

func (h *CRLHandler) getCRLInfo(ctx context.Context) (*struct {
	Version    int
	Issuer     string
	ThisUpdate time.Time
	NextUpdate time.Time
	CRLNumber  int64
	EntryCount int
	Size       int
	Algorithm  string
}, error) {
	now := time.Now()
	entryCount, err := h.countRevokedCertificates(ctx)
	if err != nil {
		entryCount = 0
	}

	crlData, err := h.generateCurrentCRL(ctx)
	if err != nil {
		return nil, err
	}

	return &struct {
		Version    int
		Issuer     string
		ThisUpdate time.Time
		NextUpdate time.Time
		CRLNumber  int64
		EntryCount int
		Size       int
		Algorithm  string
	}{
		Version:    2,
		Issuer:     "CN=QuantumCA Intermediate CA",
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		CRLNumber:  time.Now().Unix(),
		EntryCount: entryCount,
		Size:       len(crlData),
		Algorithm:  "dilithium3",
	}, nil
}

func (h *CRLHandler) GetCRLInfo(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	info, err := h.getCRLInfo(ctx)
	if err != nil {
		h.logger.LogError(err, "Failed to get CRL info", nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get CRL info"})
		return
	}

	if info == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CRL not available"})
		return
	}

	response := &CRLInfoResponse{
		Version:      info.Version,
		Issuer:       info.Issuer,
		ThisUpdate:   info.ThisUpdate.Format(time.RFC3339),
		NextUpdate:   info.NextUpdate.Format(time.RFC3339),
		CRLNumber:    info.CRLNumber,
		EntryCount:   info.EntryCount,
		Size:         info.Size,
		Algorithm:    info.Algorithm,
		DownloadURL:  "/api/v1/crl",
	}

	c.JSON(http.StatusOK, response)
}

func (h *CRLHandler) getRevokedCertificates(ctx context.Context) ([]*storage.Certificate, error) {
	query := `SELECT id, serial_number, common_name, revoked_at, revocation_reason
			  FROM certificates 
			  WHERE status = 'revoked' 
			  ORDER BY revoked_at DESC`

	rows, err := h.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*storage.Certificate
	for rows.Next() {
		cert := &storage.Certificate{}
		var revokedAt sql.NullTime
		var revocationReason sql.NullString

		err := rows.Scan(&cert.ID, &cert.SerialNumber, &cert.CommonName, 
			&revokedAt, &revocationReason)
		if err != nil {
			continue
		}

		if revokedAt.Valid {
			cert.RevokedAt = &revokedAt.Time
		}
		if revocationReason.Valid {
			cert.RevocationReason = revocationReason.String
		}

		certificates = append(certificates, cert)
	}

	return certificates, nil
}

func (h *CRLHandler) countRevokedCertificates(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM certificates WHERE status = 'revoked'`
	
	var count int
	err := h.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}