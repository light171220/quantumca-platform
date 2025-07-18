package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/services"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type CertificateHandler struct {
	db             *sql.DB
	config         *utils.Config
	logger         *utils.Logger
	issuer         *ca.Issuer
	metricsService *services.MetricsService
	validator      *ca.DomainValidator
	domainService  *services.DomainService
}

type IssueCertRequest struct {
	CommonName      string   `json:"common_name" binding:"required,fqdn,max=255"`
	SubjectAltNames []string `json:"subject_alt_names" binding:"omitempty,dive,fqdn,max=255"`
	ValidityDays    int      `json:"validity_days" binding:"omitempty,min=1,max=825"`
	TemplateID      int      `json:"template_id" binding:"required,min=1"`
	Algorithm       string   `json:"algorithm" binding:"omitempty"`
	UseMultiPQC     bool     `json:"use_multi_pqc"`
	KEMAlgorithm    string   `json:"kem_algorithm" binding:"omitempty"`
	KeyUsage        []string `json:"key_usage" binding:"omitempty"`
	ExtKeyUsage     []string `json:"ext_key_usage" binding:"omitempty"`
}

type CertificateResponse struct {
	ID                   int      `json:"id"`
	SerialNumber         string   `json:"serial_number"`
	CommonName           string   `json:"common_name"`
	SubjectAltNames      []string `json:"subject_alt_names"`
	Certificate          string   `json:"certificate,omitempty"`
	PrivateKey           string   `json:"private_key,omitempty"`
	Algorithms           []string `json:"algorithms"`
	IsMultiPQC          bool     `json:"is_multi_pqc"`
	HasKEM              bool     `json:"has_kem"`
	MultiPQCCertificates []string `json:"multi_pqc_certificates,omitempty"`
	MultiPQCPrivateKeys  []string `json:"multi_pqc_private_keys,omitempty"`
	KEMPublicKeyPEM     string   `json:"kem_public_key_pem,omitempty"`
	KEMPrivateKeyPEM    string   `json:"kem_private_key_pem,omitempty"`
	Fingerprint         string   `json:"fingerprint"`
	KeyID               string   `json:"key_id"`
	NotBefore           string   `json:"not_before"`
	NotAfter            string   `json:"not_after"`
	Status              string   `json:"status"`
	CreatedAt           string   `json:"created_at"`
	ExpiresIn           int      `json:"expires_in"`
}

type CertificateListResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
	Total        int                   `json:"total"`
	Page         int                   `json:"page"`
	PageSize     int                   `json:"page_size"`
	TotalPages   int                   `json:"total_pages"`
}

func NewCertificateHandler(db *sql.DB, config *utils.Config, logger *utils.Logger, metricsService *services.MetricsService) *CertificateHandler {
	return &CertificateHandler{
		db:             db,
		config:         config,
		logger:         logger,
		issuer:         ca.NewIssuer(config),
		metricsService: metricsService,
		validator:      ca.NewDomainValidator(),
		domainService:  services.NewDomainService(db, logger),
	}
}

func (h *CertificateHandler) Issue(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	var req IssueCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.LogError(err, "Invalid certificate request", map[string]interface{}{
			"ip": c.ClientIP(),
		})
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

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		h.logger.LogError(err, "Failed to begin transaction", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database transaction error"})
		return
	}
	defer tx.Rollback()

	customer, err := storage.GetCustomerWithContextTx(ctx, tx, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get customer", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	template, err := h.getAndValidateTemplate(ctx, req.TemplateID)
	if err != nil {
		h.logger.LogError(err, "Template validation failed", map[string]interface{}{
			"template_id": req.TemplateID,
			"customer_id": custID,
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validateCertificateRequest(&req, template); err != nil {
		h.logger.LogError(err, "Certificate request validation failed", map[string]interface{}{
			"customer_id": custID,
			"common_name": req.CommonName,
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.checkCertificateQuotaWithTx(ctx, tx, custID); err != nil {
		h.logger.LogError(err, "Certificate quota exceeded", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	domains := []string{req.CommonName}
	domains = append(domains, req.SubjectAltNames...)
	if err := h.domainService.ValidateDomainsForCertificate(custID, domains); err != nil {
		h.logger.LogError(err, "Domain validation failed", map[string]interface{}{
			"customer_id": custID,
			"domains":     domains,
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	certRequest := h.buildCertificateRequest(&req, template, customer)
	
	cert, err := h.issuer.IssueCertificate(certRequest)
	if err != nil {
		h.logger.LogError(err, "Failed to issue certificate", map[string]interface{}{
			"customer_id": custID,
			"common_name": req.CommonName,
			"template_id": req.TemplateID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue certificate"})
		return
	}

	certID, err := h.storeCertificateWithTx(ctx, tx, custID, &req, cert)
	if err != nil {
		h.logger.LogError(err, "Failed to store certificate", map[string]interface{}{
			"customer_id":   custID,
			"serial_number": cert.SerialNumber,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate"})
		return
	}

	if err := tx.Commit(); err != nil {
		h.logger.LogError(err, "Failed to commit transaction", map[string]interface{}{
			"customer_id":   custID,
			"certificate_id": certID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete certificate issuance"})
		return
	}

	h.logCertificateEvent("certificate_issued", certID, custID, &req, cert)

	if h.metricsService != nil {
		h.metricsService.RecordCertificateIssued(customer.Tier)
	}

	response := h.buildCertificateResponse(certID, &req, cert)
	c.JSON(http.StatusCreated, response)
}

func (h *CertificateHandler) List(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

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

	page := 1
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 20
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	status := c.Query("status")
	commonName := c.Query("common_name")

	certificates, total, err := h.getCertificatesPaginated(ctx, custID, page, pageSize, status, commonName)
	if err != nil {
		h.logger.LogError(err, "Failed to get certificates", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificates"})
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	response := &CertificateListResponse{
		Certificates: certificates,
		Total:        total,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func (h *CertificateHandler) Get(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
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
		h.logger.LogError(err, "Failed to get certificate", map[string]interface{}{
			"certificate_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate"})
		return
	}

	if cert.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	expiresIn := int(time.Until(cert.NotAfter).Hours() / 24)

	response := &CertificateResponse{
		ID:                   cert.ID,
		SerialNumber:         cert.SerialNumber,
		CommonName:           cert.CommonName,
		SubjectAltNames:      cert.SubjectAltNames,
		Certificate:          cert.CertificatePEM,
		Algorithms:           cert.Algorithms,
		IsMultiPQC:          cert.IsMultiPQC,
		HasKEM:              cert.HasKEM,
		MultiPQCCertificates: cert.MultiPQCCertificates,
		MultiPQCPrivateKeys:  cert.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     cert.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    cert.KEMPrivateKeyPEM,
		Fingerprint:         cert.Fingerprint,
		KeyID:               cert.KeyID,
		NotBefore:           cert.NotBefore.Format(time.RFC3339),
		NotAfter:            cert.NotAfter.Format(time.RFC3339),
		Status:              cert.Status,
		CreatedAt:           cert.CreatedAt.Format(time.RFC3339),
		ExpiresIn:           expiresIn,
	}

	c.JSON(http.StatusOK, response)
}

func (h *CertificateHandler) Revoke(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
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

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		h.logger.LogError(err, "Failed to begin transaction", map[string]interface{}{
			"certificate_id": id,
			"customer_id":    custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database transaction error"})
		return
	}
	defer tx.Rollback()

	cert, err := storage.GetCertificateWithContextTx(ctx, tx, id)
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

	if cert.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Certificate is not active"})
		return
	}

	if err := storage.RevokeCertificateWithContextTx(ctx, tx, id); err != nil {
		h.logger.LogError(err, "Failed to revoke certificate", map[string]interface{}{
			"certificate_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke certificate"})
		return
	}

	if err := tx.Commit(); err != nil {
		h.logger.LogError(err, "Failed to commit revocation", map[string]interface{}{
			"certificate_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete certificate revocation"})
		return
	}

	h.logger.LogCertificateEvent("certificate_revoked", fmt.Sprintf("%d", id), cert.CustomerID, map[string]interface{}{
		"common_name":   cert.CommonName,
		"serial_number": cert.SerialNumber,
	})

	if h.metricsService != nil {
		customer, _ := storage.GetCustomerWithContext(ctx, h.db, cert.CustomerID)
		if customer != nil {
			h.metricsService.RecordCertificateRevoked(customer.Tier)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Certificate revoked successfully"})
}

func (h *CertificateHandler) Download(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
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

	format := c.Query("format")
	filename := utils.SanitizeFilename(strings.ReplaceAll(cert.CommonName, "*", "wildcard"))
	
	switch format {
	case "pem":
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pem", filename))
		c.String(http.StatusOK, cert.CertificatePEM)
	case "key":
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s-key.pem", filename))
		c.String(http.StatusOK, cert.PrivateKeyPEM)
	case "bundle":
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s-bundle.pem", filename))
		bundle := cert.CertificatePEM + "\n" + cert.PrivateKeyPEM
		c.String(http.StatusOK, bundle)
	case "multi-pqc":
		if !cert.IsMultiPQC {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Certificate is not multi-PQC"})
			return
		}
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s-multi-pqc.json", filename))
		c.JSON(http.StatusOK, gin.H{
			"certificates": cert.MultiPQCCertificates,
			"private_keys": cert.MultiPQCPrivateKeys,
			"algorithms": cert.Algorithms,
		})
	default:
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pem", filename))
		c.String(http.StatusOK, cert.CertificatePEM)
	}
}

func (h *CertificateHandler) Renew(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
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

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		h.logger.LogError(err, "Failed to begin transaction", map[string]interface{}{
			"certificate_id": id,
			"customer_id":    custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database transaction error"})
		return
	}
	defer tx.Rollback()

	cert, err := storage.GetCertificateWithContextTx(ctx, tx, id)
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

	if cert.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot renew non-active certificate"})
		return
	}

	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysUntilExpiry > h.config.CertificateRenewalDays {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Certificate not eligible for renewal (expires in %d days)", daysUntilExpiry),
		})
		return
	}

	customer, err := storage.GetCustomerWithContextTx(ctx, tx, cert.CustomerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get customer"})
		return
	}

	algorithm := h.config.GetDefaultAlgorithm()
	if len(cert.Algorithms) > 0 {
		algorithm = cert.Algorithms[0]
	}

	newCert, err := h.issuer.IssueCertificate(&ca.CertificateRequest{
		CommonName:      cert.CommonName,
		SubjectAltNames: cert.SubjectAltNames,
		ValidityDays:    h.config.CertificateValidityDays,
		Customer:        customer,
		Algorithm:       algorithm,
		UseMultiPQC:     cert.IsMultiPQC,
	})
	if err != nil {
		h.logger.LogError(err, "Failed to renew certificate", map[string]interface{}{
			"certificate_id": id,
			"common_name":    cert.CommonName,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to renew certificate"})
		return
	}

	newCertID, err := storage.CreateCertificateWithContextTx(ctx, tx, &storage.Certificate{
		CustomerID:           cert.CustomerID,
		SerialNumber:         newCert.SerialNumber,
		CommonName:           cert.CommonName,
		SubjectAltNames:      cert.SubjectAltNames,
		CertificatePEM:       newCert.CertificatePEM,
		PrivateKeyPEM:        newCert.PrivateKeyPEM,
		Algorithms:           newCert.Algorithms,
		IsMultiPQC:          newCert.IsMultiPQC,
		HasKEM:              newCert.HasKEM,
		MultiPQCCertificates: newCert.MultiPQCCertificates,
		MultiPQCPrivateKeys:  newCert.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     newCert.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    newCert.KEMPrivateKeyPEM,
		Fingerprint:         newCert.Fingerprint,
		KeyID:               newCert.KeyID,
		NotBefore:           newCert.NotBefore,
		NotAfter:            newCert.NotAfter,
		Status:              "active",
	})
	if err != nil {
		h.logger.LogError(err, "Failed to store renewed certificate", map[string]interface{}{
			"original_cert_id": id,
			"serial_number":    newCert.SerialNumber,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store renewed certificate"})
		return
	}

	if err := storage.RevokeCertificateWithContextTx(ctx, tx, id); err != nil {
		h.logger.LogError(err, "Failed to revoke original certificate during renewal", map[string]interface{}{
			"certificate_id": id,
		})
	}

	if err := tx.Commit(); err != nil {
		h.logger.LogError(err, "Failed to commit renewal transaction", map[string]interface{}{
			"original_cert_id": id,
			"new_cert_id":      newCertID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete certificate renewal"})
		return
	}

	h.logger.LogCertificateEvent("certificate_renewed", fmt.Sprintf("%d", newCertID), cert.CustomerID, map[string]interface{}{
		"original_cert_id": id,
		"new_cert_id":      newCertID,
		"common_name":      cert.CommonName,
		"serial_number":    newCert.SerialNumber,
	})

	response := &CertificateResponse{
		ID:              newCertID,
		SerialNumber:    newCert.SerialNumber,
		CommonName:      cert.CommonName,
		SubjectAltNames: cert.SubjectAltNames,
		Certificate:     newCert.CertificatePEM,
		PrivateKey:      newCert.PrivateKeyPEM,
		Algorithms:      newCert.Algorithms,
		IsMultiPQC:     newCert.IsMultiPQC,
		HasKEM:         newCert.HasKEM,
		Fingerprint:    newCert.Fingerprint,
		KeyID:          newCert.KeyID,
		NotBefore:      newCert.NotBefore.Format(time.RFC3339),
		NotAfter:       newCert.NotAfter.Format(time.RFC3339),
		Status:         "active",
		CreatedAt:      time.Now().Format(time.RFC3339),
		ExpiresIn:      h.config.CertificateValidityDays,
	}

	c.JSON(http.StatusOK, response)
}

func (h *CertificateHandler) getAndValidateTemplate(ctx context.Context, templateID int) (*storage.CertificateTemplate, error) {
	query := `SELECT id, name, description, key_usages, ext_key_usages, validity_days, 
			  max_validity_days, is_ca, path_length, policies, status 
			  FROM certificate_templates WHERE id = ? AND status = 'active'`

	var template storage.CertificateTemplate
	var keyUsagesJSON, extKeyUsagesJSON, policiesJSON sql.NullString
	var pathLength sql.NullInt64

	err := h.db.QueryRowContext(ctx, query, templateID).Scan(
		&template.ID, &template.Name, &template.Description,
		&keyUsagesJSON, &extKeyUsagesJSON, &template.ValidityDays,
		&template.MaxValidityDays, &template.IsCA, &pathLength,
		&policiesJSON, &template.Status)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate template not found")
		}
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	if keyUsagesJSON.Valid && keyUsagesJSON.String != "" {
		if err := storage.UnmarshalJSON([]byte(keyUsagesJSON.String), &template.KeyUsages); err != nil {
			template.KeyUsages = []string{}
		}
	}

	if extKeyUsagesJSON.Valid && extKeyUsagesJSON.String != "" {
		if err := storage.UnmarshalJSON([]byte(extKeyUsagesJSON.String), &template.ExtKeyUsages); err != nil {
			template.ExtKeyUsages = []string{}
		}
	}

	if policiesJSON.Valid && policiesJSON.String != "" {
		if err := storage.UnmarshalJSON([]byte(policiesJSON.String), &template.Policies); err != nil {
			template.Policies = make(map[string]interface{})
		}
	}

	if pathLength.Valid {
		pathLengthInt := int(pathLength.Int64)
		template.PathLength = &pathLengthInt
	}

	return &template, nil
}

func (h *CertificateHandler) buildCertificateRequest(req *IssueCertRequest, template *storage.CertificateTemplate, customer *storage.Customer) *ca.CertificateRequest {
	validityDays := req.ValidityDays
	if validityDays == 0 {
		validityDays = template.ValidityDays
	}
	if validityDays > template.MaxValidityDays {
		validityDays = template.MaxValidityDays
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = h.config.GetDefaultAlgorithm()
	}

	useMultiPQC := req.UseMultiPQC || h.config.EnableMultiPQC || algorithm == "multi-pqc"

	return &ca.CertificateRequest{
		CommonName:      utils.SanitizeString(req.CommonName),
		SubjectAltNames: h.sanitizeSubjectAltNames(req.SubjectAltNames),
		ValidityDays:    validityDays,
		Customer:        customer,
		Algorithm:       algorithm,
		TemplateID:      req.TemplateID,
		UseMultiPQC:     useMultiPQC,
		KEMAlgorithm:    req.KEMAlgorithm,
	}
}

func (h *CertificateHandler) validateCertificateRequest(req *IssueCertRequest, template *storage.CertificateTemplate) error {
	if err := utils.ValidateCommonName(req.CommonName); err != nil {
		return fmt.Errorf("invalid common name: %w", err)
	}

	if err := h.validator.ValidateSubjectAltNames(req.SubjectAltNames); err != nil {
		return fmt.Errorf("invalid subject alternative names: %w", err)
	}

	if req.ValidityDays > 0 {
		if req.ValidityDays > template.MaxValidityDays {
			return fmt.Errorf("validity days exceeds template maximum (%d > %d)", req.ValidityDays, template.MaxValidityDays)
		}
		if err := utils.ValidateValidityDays(req.ValidityDays); err != nil {
			return fmt.Errorf("invalid validity days: %w", err)
		}
	}

	if req.Algorithm != "" {
		if !h.config.IsAlgorithmAllowed(req.Algorithm) {
			return fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
		}
	}

	if req.KEMAlgorithm != "" {
		kemAlgorithms := []string{"kyber512", "kyber768", "kyber1024"}
		valid := false
		for _, alg := range kemAlgorithms {
			if req.KEMAlgorithm == alg {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unsupported KEM algorithm: %s", req.KEMAlgorithm)
		}
	}

	return nil
}

func (h *CertificateHandler) sanitizeSubjectAltNames(sans []string) []string {
	var sanitized []string
	seen := make(map[string]bool)
	
	for _, san := range sans {
		clean := strings.TrimSpace(utils.SanitizeString(san))
		if len(clean) > 0 && len(clean) <= 255 && !seen[clean] {
			sanitized = append(sanitized, clean)
			seen[clean] = true
		}
	}
	return sanitized
}

func (h *CertificateHandler) checkCertificateQuota(ctx context.Context, customerID int) error {
	query := `SELECT COUNT(*) FROM certificates WHERE customer_id = ? AND status = 'active'`
	
	var count int
	err := h.db.QueryRowContext(ctx, query, customerID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check certificate quota: %w", err)
	}

	if count >= h.config.MaxCertificatesPerCustomer {
		return fmt.Errorf("certificate quota exceeded (%d/%d)", count, h.config.MaxCertificatesPerCustomer)
	}

	return nil
}

func (h *CertificateHandler) checkCertificateQuotaWithTx(ctx context.Context, tx *sql.Tx, customerID int) error {
	query := `SELECT COUNT(*) FROM certificates WHERE customer_id = ? AND status = 'active' FOR UPDATE`
	
	var count int
	err := tx.QueryRowContext(ctx, query, customerID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check certificate quota: %w", err)
	}

	if count >= h.config.MaxCertificatesPerCustomer {
		return fmt.Errorf("certificate quota exceeded (%d/%d)", count, h.config.MaxCertificatesPerCustomer)
	}

	return nil
}

func (h *CertificateHandler) storeCertificate(ctx context.Context, customerID int, req *IssueCertRequest, cert *ca.CertificateResponse) (int, error) {
	dbCert := &storage.Certificate{
		CustomerID:           customerID,
		SerialNumber:         cert.SerialNumber,
		CommonName:           utils.SanitizeString(req.CommonName),
		SubjectAltNames:      h.sanitizeSubjectAltNames(req.SubjectAltNames),
		CertificatePEM:       cert.CertificatePEM,
		PrivateKeyPEM:        cert.PrivateKeyPEM,
		Algorithms:           cert.Algorithms,
		IsMultiPQC:          cert.IsMultiPQC,
		HasKEM:              cert.HasKEM,
		MultiPQCCertificates: cert.MultiPQCCertificates,
		MultiPQCPrivateKeys:  cert.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     cert.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    cert.KEMPrivateKeyPEM,
		Fingerprint:         cert.Fingerprint,
		KeyID:               cert.KeyID,
		NotBefore:           cert.NotBefore,
		NotAfter:            cert.NotAfter,
		Status:              "active",
	}
	
	return storage.CreateCertificateWithContext(ctx, h.db, dbCert)
}

func (h *CertificateHandler) storeCertificateWithTx(ctx context.Context, tx *sql.Tx, customerID int, req *IssueCertRequest, cert *ca.CertificateResponse) (int, error) {
	dbCert := &storage.Certificate{
		CustomerID:           customerID,
		SerialNumber:         cert.SerialNumber,
		CommonName:           utils.SanitizeString(req.CommonName),
		SubjectAltNames:      h.sanitizeSubjectAltNames(req.SubjectAltNames),
		CertificatePEM:       cert.CertificatePEM,
		PrivateKeyPEM:        cert.PrivateKeyPEM,
		Algorithms:           cert.Algorithms,
		IsMultiPQC:          cert.IsMultiPQC,
		HasKEM:              cert.HasKEM,
		MultiPQCCertificates: cert.MultiPQCCertificates,
		MultiPQCPrivateKeys:  cert.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     cert.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    cert.KEMPrivateKeyPEM,
		Fingerprint:         cert.Fingerprint,
		KeyID:               cert.KeyID,
		NotBefore:           cert.NotBefore,
		NotAfter:            cert.NotAfter,
		Status:              "active",
	}
	
	return storage.CreateCertificateWithContextTx(ctx, tx, dbCert)
}

func (h *CertificateHandler) logCertificateEvent(event string, certID int, custID int, req *IssueCertRequest, cert *ca.CertificateResponse) {
	h.logger.LogCertificateEvent(event, fmt.Sprintf("%d", certID), custID, map[string]interface{}{
		"common_name":    req.CommonName,
		"serial_number":  cert.SerialNumber,
		"validity_days":  req.ValidityDays,
		"algorithms":     cert.Algorithms,
		"template_id":    req.TemplateID,
		"is_multi_pqc":   cert.IsMultiPQC,
		"has_kem":        cert.HasKEM,
	})
}

func (h *CertificateHandler) getCertificatesPaginated(ctx context.Context, customerID, page, pageSize int, status, commonName string) ([]CertificateResponse, int, error) {
	offset := (page - 1) * pageSize
	
	whereClause := "WHERE customer_id = ?"
	args := []interface{}{customerID}
	
	if status != "" {
		whereClause += " AND status = ?"
		args = append(args, status)
	}
	
	if commonName != "" {
		whereClause += " AND common_name LIKE ?"
		args = append(args, "%"+commonName+"%")
	}

	countQuery := "SELECT COUNT(*) FROM certificates " + whereClause
	var total int
	err := h.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `SELECT id, serial_number, common_name, subject_alt_names, algorithms, 
			  is_multi_pqc, has_kem, fingerprint, key_id, not_before, not_after, 
			  status, created_at FROM certificates ` + whereClause + `
			  ORDER BY created_at DESC LIMIT ? OFFSET ?`
	
	args = append(args, pageSize, offset)
	
	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var certificates []CertificateResponse
	for rows.Next() {
		var cert CertificateResponse
		var algorithmsJSON, subjectAltNamesJSON string
		var notBefore, notAfter, createdAt time.Time

		err := rows.Scan(&cert.ID, &cert.SerialNumber, &cert.CommonName,
			&subjectAltNamesJSON, &algorithmsJSON, &cert.IsMultiPQC, &cert.HasKEM,
			&cert.Fingerprint, &cert.KeyID, &notBefore, &notAfter,
			&cert.Status, &createdAt)
		if err != nil {
			continue
		}

		if algorithmsJSON != "" {
			if err := storage.UnmarshalJSON([]byte(algorithmsJSON), &cert.Algorithms); err != nil {
				cert.Algorithms = []string{}
			}
		}

		if subjectAltNamesJSON != "" {
			if err := storage.UnmarshalJSON([]byte(subjectAltNamesJSON), &cert.SubjectAltNames); err != nil {
				cert.SubjectAltNames = []string{}
			}
		}

		cert.NotBefore = notBefore.Format(time.RFC3339)
		cert.NotAfter = notAfter.Format(time.RFC3339)
		cert.CreatedAt = createdAt.Format(time.RFC3339)
		cert.ExpiresIn = int(time.Until(notAfter).Hours() / 24)

		certificates = append(certificates, cert)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, err
	}

	return certificates, total, nil
}

func (h *CertificateHandler) buildCertificateResponse(certID int, req *IssueCertRequest, cert *ca.CertificateResponse) *CertificateResponse {
	return &CertificateResponse{
		ID:                   certID,
		SerialNumber:         cert.SerialNumber,
		CommonName:           req.CommonName,
		SubjectAltNames:      req.SubjectAltNames,
		Certificate:          cert.CertificatePEM,
		PrivateKey:           cert.PrivateKeyPEM,
		Algorithms:           cert.Algorithms,
		IsMultiPQC:          cert.IsMultiPQC,
		HasKEM:              cert.HasKEM,
		MultiPQCCertificates: cert.MultiPQCCertificates,
		MultiPQCPrivateKeys:  cert.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     cert.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    cert.KEMPrivateKeyPEM,
		Fingerprint:         cert.Fingerprint,
		KeyID:               cert.KeyID,
		NotBefore:           cert.NotBefore.Format(time.RFC3339),
		NotAfter:            cert.NotAfter.Format(time.RFC3339),
		Status:              "active",
		CreatedAt:           time.Now().Format(time.RFC3339),
		ExpiresIn:           req.ValidityDays,
	}
}