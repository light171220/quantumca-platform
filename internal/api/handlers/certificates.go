package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type CertificateHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
	issuer *ca.Issuer
}

func NewCertificateHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *CertificateHandler {
	return &CertificateHandler{
		db:     db,
		config: config,
		logger: logger,
		issuer: ca.NewIssuer(config),
	}
}

type IssueCertRequest struct {
	CustomerID      int      `json:"customer_id" binding:"required"`
	CommonName      string   `json:"common_name" binding:"required"`
	SubjectAltNames []string `json:"subject_alt_names"`
	ValidityDays    int      `json:"validity_days"`
}

type CertificateResponse struct {
	ID              int      `json:"id"`
	SerialNumber    string   `json:"serial_number"`
	CommonName      string   `json:"common_name"`
	SubjectAltNames []string `json:"subject_alt_names"`
	Certificate     string   `json:"certificate"`
	PrivateKey      string   `json:"private_key,omitempty"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	Status          string   `json:"status"`
	CreatedAt       string   `json:"created_at"`
}

func (h *CertificateHandler) Issue(c *gin.Context) {
	var req IssueCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	customer, err := storage.GetCustomer(h.db, req.CustomerID)
	if err != nil {
		h.logger.Error("Failed to get customer:", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	domains, err := storage.GetCustomerDomains(h.db, req.CustomerID)
	if err != nil {
		h.logger.Error("Failed to get customer domains:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get domains"})
		return
	}

	if !h.validateDomains(req.CommonName, req.SubjectAltNames, domains) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain not verified"})
		return
	}

	if req.ValidityDays == 0 {
		req.ValidityDays = h.config.CertificateValidityDays
	}

	cert, err := h.issuer.IssueCertificate(&ca.CertificateRequest{
		CommonName:      req.CommonName,
		SubjectAltNames: req.SubjectAltNames,
		ValidityDays:    req.ValidityDays,
		Customer:        customer,
	})
	if err != nil {
		h.logger.Error("Failed to issue certificate:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue certificate"})
		return
	}

	certID, err := storage.CreateCertificate(h.db, &storage.Certificate{
		CustomerID:      req.CustomerID,
		SerialNumber:    cert.SerialNumber,
		CommonName:      req.CommonName,
		SubjectAltNames: req.SubjectAltNames,
		CertificatePEM:  cert.CertificatePEM,
		PrivateKeyPEM:   cert.PrivateKeyPEM,
		Algorithms:      cert.Algorithms,
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		Status:          "active",
	})
	if err != nil {
		h.logger.Error("Failed to store certificate:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate"})
		return
	}

	response := &CertificateResponse{
		ID:              certID,
		SerialNumber:    cert.SerialNumber,
		CommonName:      req.CommonName,
		SubjectAltNames: req.SubjectAltNames,
		Certificate:     cert.CertificatePEM,
		PrivateKey:      cert.PrivateKeyPEM,
		NotBefore:       cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:        cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Status:          "active",
	}

	c.JSON(http.StatusCreated, response)
}

func (h *CertificateHandler) List(c *gin.Context) {
	customerIDStr := c.Query("customer_id")
	if customerIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "customer_id required"})
		return
	}

	customerID, err := strconv.Atoi(customerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer_id"})
		return
	}

	certificates, err := storage.GetCustomerCertificates(h.db, customerID)
	if err != nil {
		h.logger.Error("Failed to get certificates:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificates"})
		return
	}

	var response []CertificateResponse
	for _, cert := range certificates {
		response = append(response, CertificateResponse{
			ID:              cert.ID,
			SerialNumber:    cert.SerialNumber,
			CommonName:      cert.CommonName,
			SubjectAltNames: cert.SubjectAltNames,
			Certificate:     cert.CertificatePEM,
			NotBefore:       cert.NotBefore.Format("2006-01-02T15:04:05Z"),
			NotAfter:        cert.NotAfter.Format("2006-01-02T15:04:05Z"),
			Status:          cert.Status,
			CreatedAt:       cert.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	c.JSON(http.StatusOK, response)
}

func (h *CertificateHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	cert, err := storage.GetCertificate(h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		h.logger.Error("Failed to get certificate:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate"})
		return
	}

	response := &CertificateResponse{
		ID:              cert.ID,
		SerialNumber:    cert.SerialNumber,
		CommonName:      cert.CommonName,
		SubjectAltNames: cert.SubjectAltNames,
		Certificate:     cert.CertificatePEM,
		NotBefore:       cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:        cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Status:          cert.Status,
		CreatedAt:       cert.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	c.JSON(http.StatusOK, response)
}

func (h *CertificateHandler) Revoke(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	if err := storage.RevokeCertificate(h.db, id); err != nil {
		h.logger.Error("Failed to revoke certificate:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke certificate"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Certificate revoked successfully"})
}

func (h *CertificateHandler) validateDomains(commonName string, subjectAltNames []string, domains []*storage.Domain) bool {
	verifiedDomains := make(map[string]bool)
	for _, domain := range domains {
		if domain.IsVerified {
			verifiedDomains[domain.DomainName] = true
		}
	}

	if !verifiedDomains[commonName] {
		return false
	}

	for _, san := range subjectAltNames {
		if !verifiedDomains[san] {
			return false
		}
	}

	return true
}