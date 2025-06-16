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

type IntermediateHandler struct {
	db             *sql.DB
	config         *utils.Config
	logger         *utils.Logger
	issuer         *ca.Issuer
	metricsService *services.MetricsService
}

func NewIntermediateHandler(db *sql.DB, config *utils.Config, logger *utils.Logger, metricsService *services.MetricsService) *IntermediateHandler {
	return &IntermediateHandler{
		db:             db,
		config:         config,
		logger:         logger,
		issuer:         ca.NewIssuer(config),
		metricsService: metricsService,
	}
}

type CreateIntermediateCARequest struct {
	CommonName string `json:"common_name" binding:"required,max=255"`
	Country    string `json:"country" binding:"required,len=2"`
	State      string `json:"state" binding:"required,max=255"`
	City       string `json:"city" binding:"required,max=255"`
	Org        string `json:"organization" binding:"required,max=255"`
	OrgUnit    string `json:"organizational_unit" binding:"omitempty,max=255"`
}

type IntermediateCAResponse struct {
	ID          int    `json:"id"`
	CustomerID  int    `json:"customer_id"`
	CommonName  string `json:"common_name"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key,omitempty"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type IntermediateCAListResponse struct {
	IntermediateCAs []IntermediateCAResponse `json:"intermediate_cas"`
	Total           int                      `json:"total"`
	Page            int                      `json:"page"`
	PageSize        int                      `json:"page_size"`
	TotalPages      int                      `json:"total_pages"`
}

func (h *IntermediateHandler) Create(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var req CreateIntermediateCARequest
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

	customer, err := storage.GetCustomerWithContext(ctx, h.db, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get customer", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	if customer.Tier < 2 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Intermediate CA service requires Tier 2 or higher"})
		return
	}

	intermediateCert, err := h.issuer.IssueIntermediateCA(&ca.IntermediateCARequest{
		CommonName: utils.SanitizeString(req.CommonName),
		Country:    utils.SanitizeString(req.Country),
		State:      utils.SanitizeString(req.State),
		City:       utils.SanitizeString(req.City),
		Org:        utils.SanitizeString(req.Org),
		OrgUnit:    utils.SanitizeString(req.OrgUnit),
		Customer:   customer,
	})
	if err != nil {
		h.logger.LogError(err, "Failed to issue intermediate CA", map[string]interface{}{
			"customer_id": custID,
			"common_name": req.CommonName,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue intermediate CA"})
		return
	}

	id, err := storage.CreateIntermediateCAWithContext(ctx, h.db, &storage.IntermediateCA{
		CustomerID:     custID,
		CommonName:     utils.SanitizeString(req.CommonName),
		CertificatePEM: intermediateCert.CertificatePEM,
		PrivateKeyPEM:  intermediateCert.PrivateKeyPEM,
		NotBefore:      intermediateCert.NotBefore,
		NotAfter:       intermediateCert.NotAfter,
		Status:         "active",
	})
	if err != nil {
		h.logger.LogError(err, "Failed to store intermediate CA", map[string]interface{}{
			"customer_id": custID,
			"common_name": req.CommonName,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store intermediate CA"})
		return
	}

	h.logger.LogCertificateEvent("intermediate_ca_created", fmt.Sprintf("%d", id), custID, map[string]interface{}{
		"common_name":   req.CommonName,
		"serial_number": intermediateCert.SerialNumber,
		"algorithms":    intermediateCert.Algorithms,
	})

	if h.metricsService != nil {
		h.metricsService.RecordCertificateIssued(customer.Tier)
	}

	response := &IntermediateCAResponse{
		ID:          id,
		CustomerID:  custID,
		CommonName:  req.CommonName,
		Certificate: intermediateCert.CertificatePEM,
		PrivateKey:  intermediateCert.PrivateKeyPEM,
		NotBefore:   intermediateCert.NotBefore.Format(time.RFC3339),
		NotAfter:    intermediateCert.NotAfter.Format(time.RFC3339),
		Status:      "active",
		CreatedAt:   intermediateCert.NotBefore.Format(time.RFC3339),
		UpdatedAt:   intermediateCert.NotBefore.Format(time.RFC3339),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *IntermediateHandler) List(c *gin.Context) {
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

	intermediateCAs, err := storage.GetCustomerIntermediateCAsWithContext(ctx, h.db, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get customer intermediate CAs", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get intermediate CAs"})
		return
	}

	total := len(intermediateCAs)
	totalPages := (total + pageSize - 1) / pageSize

	start := (page - 1) * pageSize
	end := start + pageSize
	if end > total {
		end = total
	}

	var paginatedCAs []IntermediateCAResponse
	for i := start; i < end && i < len(intermediateCAs); i++ {
		ca := intermediateCAs[i]
		response := IntermediateCAResponse{
			ID:          ca.ID,
			CustomerID:  ca.CustomerID,
			CommonName:  ca.CommonName,
			Certificate: ca.CertificatePEM,
			NotBefore:   ca.NotBefore.Format(time.RFC3339),
			NotAfter:    ca.NotAfter.Format(time.RFC3339),
			Status:      ca.Status,
			CreatedAt:   ca.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   ca.UpdatedAt.Format(time.RFC3339),
		}

		paginatedCAs = append(paginatedCAs, response)
	}

	response := &IntermediateCAListResponse{
		IntermediateCAs: paginatedCAs,
		Total:           total,
		Page:            page,
		PageSize:        pageSize,
		TotalPages:      totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func (h *IntermediateHandler) Get(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid intermediate CA ID"})
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

	intermediateCA, err := storage.GetIntermediateCAWithContext(ctx, h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Intermediate CA not found"})
			return
		}
		h.logger.LogError(err, "Failed to get intermediate CA", map[string]interface{}{
			"intermediate_ca_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get intermediate CA"})
		return
	}

	if intermediateCA.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	response := &IntermediateCAResponse{
		ID:          intermediateCA.ID,
		CustomerID:  intermediateCA.CustomerID,
		CommonName:  intermediateCA.CommonName,
		Certificate: intermediateCA.CertificatePEM,
		NotBefore:   intermediateCA.NotBefore.Format(time.RFC3339),
		NotAfter:    intermediateCA.NotAfter.Format(time.RFC3339),
		Status:      intermediateCA.Status,
		CreatedAt:   intermediateCA.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   intermediateCA.UpdatedAt.Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *IntermediateHandler) Revoke(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid intermediate CA ID"})
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

	intermediateCA, err := storage.GetIntermediateCAWithContext(ctx, h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Intermediate CA not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get intermediate CA"})
		return
	}

	if intermediateCA.CustomerID != custID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if intermediateCA.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Intermediate CA is not active"})
		return
	}

	query := `UPDATE intermediate_cas SET status = 'revoked', updated_at = CURRENT_TIMESTAMP 
			  WHERE id = ? AND customer_id = ?`
	
	result, err := h.db.ExecContext(ctx, query, id, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to revoke intermediate CA", map[string]interface{}{
			"intermediate_ca_id": id,
			"customer_id":        custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke intermediate CA"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Intermediate CA not found"})
		return
	}

	h.logger.LogCertificateEvent("intermediate_ca_revoked", fmt.Sprintf("%d", id), custID, map[string]interface{}{
		"common_name": intermediateCA.CommonName,
	})

	if h.metricsService != nil {
		customer, _ := storage.GetCustomerWithContext(ctx, h.db, custID)
		if customer != nil {
			h.metricsService.RecordCertificateRevoked(customer.Tier)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Intermediate CA revoked successfully"})
}