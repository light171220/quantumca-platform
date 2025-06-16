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
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type DomainHandler struct {
	db        *sql.DB
	config    *utils.Config
	logger    *utils.Logger
	validator *ca.DomainValidator
}

func NewDomainHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *DomainHandler {
	return &DomainHandler{
		db:        db,
		config:    config,
		logger:    logger,
		validator: ca.NewDomainValidator(),
	}
}

type AddDomainRequest struct {
	DomainName string `json:"domain_name" binding:"required,fqdn,max=255"`
}

type DomainResponse struct {
	ID               int    `json:"id"`
	CustomerID       int    `json:"customer_id"`
	DomainName       string `json:"domain_name"`
	ValidationToken  string `json:"validation_token"`
	IsVerified       bool   `json:"is_verified"`
	VerifiedAt       string `json:"verified_at,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type DomainListResponse struct {
	Domains    []DomainResponse `json:"domains"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
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

	token, err := h.validator.GenerateValidationToken()
	if err != nil {
		h.logger.LogError(err, "Failed to generate validation token", nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate validation token"})
		return
	}

	domain := &storage.Domain{
		CustomerID:      custID,
		DomainName:      utils.SanitizeString(req.DomainName),
		ValidationToken: token,
		IsVerified:      false,
	}

	id, err := storage.CreateDomainWithContext(ctx, h.db, domain)
	if err != nil {
		h.logger.LogError(err, "Failed to create domain", map[string]interface{}{
			"customer_id": custID,
			"domain_name": req.DomainName,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create domain"})
		return
	}

	h.logger.LogCertificateEvent("domain_added", fmt.Sprintf("%d", id), custID, map[string]interface{}{
		"domain_name": req.DomainName,
	})

	response := &DomainResponse{
		ID:              id,
		CustomerID:      domain.CustomerID,
		DomainName:      domain.DomainName,
		ValidationToken: domain.ValidationToken,
		IsVerified:      domain.IsVerified,
		CreatedAt:       domain.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       domain.CreatedAt.Format(time.RFC3339),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *DomainHandler) Verify(c *gin.Context) {
	_, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
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

	if domain.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain already verified"})
		return
	}

	if err := storage.VerifyDomain(h.db, id); err != nil {
		h.logger.LogError(err, "Failed to verify domain", map[string]interface{}{
			"domain_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify domain"})
		return
	}

	h.logger.LogCertificateEvent("domain_verified", fmt.Sprintf("%d", id), custID, map[string]interface{}{
		"domain_name": domain.DomainName,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Domain verified successfully"})
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

	domains, err := storage.GetCustomerDomainsWithContext(ctx, h.db, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get customer domains", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get domains"})
		return
	}

	total := len(domains)
	totalPages := (total + pageSize - 1) / pageSize

	start := (page - 1) * pageSize
	end := start + pageSize
	if end > total {
		end = total
	}

	var paginatedDomains []DomainResponse
	for i := start; i < end && i < len(domains); i++ {
		domain := domains[i]
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