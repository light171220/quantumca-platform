package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/services"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type DomainHandler struct {
	db            *sql.DB
	config        *utils.Config
	logger        *utils.Logger
	validator     *ca.DomainValidator
	domainService *services.DomainService
}

func NewDomainHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *DomainHandler {
	return &DomainHandler{
		db:            db,
		config:        config,
		logger:        logger,
		validator:     ca.NewDomainValidator(),
		domainService: services.NewDomainService(db, logger),
	}
}

type AddDomainRequest struct {
	DomainName       string `json:"domain_name" binding:"required,fqdn,max=255"`
	ValidationMethod string `json:"validation_method" binding:"omitempty,oneof=dns-txt http-01"`
}

type VerifyDomainRequest struct {
	ValidationMethod string `json:"validation_method" binding:"omitempty,oneof=dns-txt http-01"`
	Token           string `json:"token" binding:"omitempty"`
}

type DomainResponse struct {
	ID               int                  `json:"id"`
	CustomerID       int                  `json:"customer_id"`
	DomainName       string               `json:"domain_name"`
	ValidationToken  string               `json:"validation_token"`
	IsVerified       bool                 `json:"is_verified"`
	VerifiedAt       string               `json:"verified_at,omitempty"`
	CreatedAt        string               `json:"created_at"`
	UpdatedAt        string               `json:"updated_at"`
	ValidationMethod string               `json:"validation_method,omitempty"`
	DNSChallenge     *ca.DNSChallenge     `json:"dns_challenge,omitempty"`
	HTTPChallenge    *ca.HTTPChallenge    `json:"http_challenge,omitempty"`
}

type DomainListResponse struct {
	Domains    []DomainResponse `json:"domains"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

type DomainValidationResponse struct {
	Domain           string               `json:"domain"`
	ValidationMethod string               `json:"validation_method"`
	DNSChallenge     *ca.DNSChallenge     `json:"dns_challenge,omitempty"`
	HTTPChallenge    *ca.HTTPChallenge    `json:"http_challenge,omitempty"`
	Instructions     ValidationInstructions `json:"instructions"`
}

type ValidationInstructions struct {
	DNS  string `json:"dns,omitempty"`
	HTTP string `json:"http,omitempty"`
}

func (h *DomainHandler) Add(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req AddDomainRequest
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

	if err := utils.ValidateDomainName(req.DomainName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := storage.GetCustomerWithContext(ctx, h.db, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get customer", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	domain, err := h.domainService.AddDomain(custID, utils.SanitizeString(req.DomainName))
	if err != nil {
		h.logger.LogError(err, "Failed to add domain", map[string]interface{}{
			"customer_id": custID,
			"domain_name": req.DomainName,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add domain"})
		return
	}

	validationMethod := req.ValidationMethod
	if validationMethod == "" {
		validationMethod = "dns-txt"
	}

	response := &DomainResponse{
		ID:               domain.ID,
		CustomerID:       domain.CustomerID,
		DomainName:       domain.DomainName,
		ValidationToken:  domain.ValidationToken,
		IsVerified:       domain.IsVerified,
		CreatedAt:        domain.CreatedAt.Format(time.RFC3339),
		UpdatedAt:        domain.CreatedAt.Format(time.RFC3339),
		ValidationMethod: validationMethod,
	}

	if validationMethod == "dns-txt" {
		dnsChallenge, err := h.domainService.CreateDNSChallenge(custID, req.DomainName)
		if err == nil {
			response.DNSChallenge = dnsChallenge
		}
	} else if validationMethod == "http-01" {
		httpChallenge, err := h.domainService.CreateHTTPChallenge(custID, req.DomainName)
		if err == nil {
			response.HTTPChallenge = httpChallenge
		}
	}

	h.logger.LogCertificateEvent("domain_added", fmt.Sprintf("%d", domain.ID), custID, map[string]interface{}{
		"domain_name":       req.DomainName,
		"validation_method": validationMethod,
	})

	c.JSON(http.StatusCreated, response)
}

func (h *DomainHandler) Verify(c *gin.Context) {
	_, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain ID"})
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

	var req VerifyDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.ValidationMethod = "dns-txt"
	}

	domain, err := storage.GetDomain(h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get domain"})
		return
	}

	if domain.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain already verified"})
		return
	}

	token := req.Token
	if token == "" {
		token = domain.ValidationToken
	}

	var result *ca.ValidationResult
	var validationErr error

	if req.ValidationMethod == "http-01" {
		result, validationErr = h.validator.ValidateDomainControlActual(domain.DomainName, token)
	} else {
		result, validationErr = h.validator.ValidateDomainControlActual(domain.DomainName, token)
	}

	if validationErr != nil {
		h.logger.LogError(validationErr, "Domain validation error", map[string]interface{}{
			"domain_id":   id,
			"domain_name": domain.DomainName,
			"method":      req.ValidationMethod,
		})
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Domain validation failed",
			"details": validationErr.Error(),
		})
		return
	}

	if !result.Valid {
		h.logger.LogSecurityEvent("domain_validation_failed", "", c.ClientIP(), map[string]interface{}{
			"domain_id":   id,
			"domain_name": domain.DomainName,
			"method":      result.Method,
			"details":     result.Details,
		})
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Domain validation failed",
			"method":  result.Method,
			"details": result.Details,
		})
		return
	}

	if err := h.domainService.ValidateDomain(id, custID); err != nil {
		h.logger.LogError(err, "Failed to mark domain as verified", map[string]interface{}{
			"domain_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify domain"})
		return
	}

	h.logger.LogCertificateEvent("domain_verified", fmt.Sprintf("%d", id), custID, map[string]interface{}{
		"domain_name": domain.DomainName,
		"method":      result.Method,
		"details":     result.Details,
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "Domain verified successfully",
		"method":  result.Method,
		"details": result.Details,
	})
}

func (h *DomainHandler) List(c *gin.Context) {
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
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 && p <= 1000 {
			page = p
		}
	}

	pageSize := 20
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	verificationStatus := c.Query("verified")

	domains, err := storage.GetCustomerDomainsWithContext(ctx, h.db, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get customer domains", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get domains"})
		return
	}

	filteredDomains := make([]*storage.Domain, 0)
	for _, domain := range domains {
		if verificationStatus == "true" && !domain.IsVerified {
			continue
		}
		if verificationStatus == "false" && domain.IsVerified {
			continue
		}
		filteredDomains = append(filteredDomains, domain)
	}

	total := len(filteredDomains)
	totalPages := (total + pageSize - 1) / pageSize

	start := (page - 1) * pageSize
	end := start + pageSize
	if end > total {
		end = total
	}

	var paginatedDomains []DomainResponse
	for i := start; i < end && i < len(filteredDomains); i++ {
		domain := filteredDomains[i]
		response := DomainResponse{
			ID:              domain.ID,
			CustomerID:      domain.CustomerID,
			DomainName:      domain.DomainName,
			ValidationToken: domain.ValidationToken,
			IsVerified:      domain.IsVerified,
			CreatedAt:       domain.CreatedAt.Format(time.RFC3339),
			UpdatedAt:       domain.UpdatedAt.Format(time.RFC3339),
		}

		if domain.VerifiedAt != nil {
			response.VerifiedAt = domain.VerifiedAt.Format(time.RFC3339)
		}

		if !domain.IsVerified {
			dnsChallenge, err := h.domainService.CreateDNSChallenge(custID, domain.DomainName)
			if err == nil {
				response.DNSChallenge = dnsChallenge
			}

			httpChallenge, err := h.domainService.CreateHTTPChallenge(custID, domain.DomainName)
			if err == nil {
				response.HTTPChallenge = httpChallenge
			}
		}

		paginatedDomains = append(paginatedDomains, response)
	}

	response := &DomainListResponse{
		Domains:    paginatedDomains,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func (h *DomainHandler) Delete(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain ID"})
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

	domain, err := storage.GetDomain(h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get domain"})
		return
	}

	if domain.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	activeCertificatesQuery := `SELECT COUNT(*) FROM certificates 
								WHERE customer_id = ? AND status = 'active' 
								AND (common_name = ? OR subject_alt_names LIKE ?)`
	var activeCertCount int
	err = h.db.QueryRowContext(ctx, activeCertificatesQuery, custID, domain.DomainName, "%"+domain.DomainName+"%").Scan(&activeCertCount)
	if err == nil && activeCertCount > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error":   "Cannot delete domain with active certificates",
			"details": fmt.Sprintf("Domain has %d active certificates", activeCertCount),
		})
		return
	}

	query := `DELETE FROM domains WHERE id = ? AND customer_id = ?`
	result, err := h.db.ExecContext(ctx, query, id, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to delete domain", map[string]interface{}{
			"domain_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete domain"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	h.logger.LogCertificateEvent("domain_deleted", fmt.Sprintf("%d", id), custID, map[string]interface{}{
		"domain_name": domain.DomainName,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Domain deleted successfully"})
}

func (h *DomainHandler) GetValidationInfo(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain ID"})
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

	domain, err := storage.GetDomain(h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get domain"})
		return
	}

	if domain.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.IsVerified {
		c.JSON(http.StatusOK, gin.H{
			"domain":      domain.DomainName,
			"is_verified": true,
			"verified_at": domain.VerifiedAt.Format(time.RFC3339),
		})
		return
	}

	dnsChallenge, err := h.domainService.CreateDNSChallenge(custID, domain.DomainName)
	if err != nil {
		h.logger.LogError(err, "Failed to create DNS challenge", map[string]interface{}{
			"domain_id": id,
		})
	}

	httpChallenge, err := h.domainService.CreateHTTPChallenge(custID, domain.DomainName)
	if err != nil {
		h.logger.LogError(err, "Failed to create HTTP challenge", map[string]interface{}{
			"domain_id": id,
		})
	}

	response := &DomainValidationResponse{
		Domain:           domain.DomainName,
		ValidationMethod: "both",
		DNSChallenge:     dnsChallenge,
		HTTPChallenge:    httpChallenge,
		Instructions: ValidationInstructions{
			DNS: fmt.Sprintf("Add a TXT record for %s with value: %s", 
				dnsChallenge.RecordName, dnsChallenge.RecordValue),
			HTTP: fmt.Sprintf("Place file at %s containing: %s", 
				httpChallenge.Path, httpChallenge.Content),
		},
	}

	c.JSON(http.StatusOK, response)
}

func (h *DomainHandler) CheckDomainAvailability(c *gin.Context) {
	domainName := c.Query("domain")
	if domainName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain name required"})
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

	if err := utils.ValidateDomainName(domainName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":     "Invalid domain name",
			"details":   err.Error(),
			"available": false,
		})
		return
	}

	isVerified, err := h.domainService.IsVerified(custID, domainName)
	if err != nil && err != sql.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check domain status"})
		return
	}

	if err := h.validator.CheckDomainReachability(domainName); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"domain":      domainName,
			"available":   false,
			"reachable":   false,
			"verified":    isVerified,
			"details":     err.Error(),
		})
		return
	}

	caaErr := h.validator.VerifyCAA(domainName)
	caaAuthorized := caaErr == nil

	c.JSON(http.StatusOK, gin.H{
		"domain":        domainName,
		"available":     true,
		"reachable":     true,
		"verified":      isVerified,
		"caa_authorized": caaAuthorized,
		"caa_details":   func() string {
			if caaErr != nil {
				return caaErr.Error()
			}
			return "CAA authorization valid"
		}(),
	})
}