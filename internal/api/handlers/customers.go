package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/services"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type CustomerHandler struct {
	db             *sql.DB
	config         *utils.Config
	logger         *utils.Logger
	metricsService *services.MetricsService
}

func NewCustomerHandler(db *sql.DB, config *utils.Config, logger *utils.Logger, metricsService *services.MetricsService) *CustomerHandler {
	return &CustomerHandler{
		db:             db,
		config:         config,
		logger:         logger,
		metricsService: metricsService,
	}
}

type CreateCustomerRequest struct {
	CompanyName string `json:"company_name" binding:"required,min=2,max=255"`
	Email       string `json:"email" binding:"required,email,max=255"`
	Tier        int    `json:"tier" binding:"required,min=1,max=3"`
}

type UpdateCustomerRequest struct {
	CompanyName string `json:"company_name" binding:"omitempty,min=2,max=255"`
	Email       string `json:"email" binding:"omitempty,email,max=255"`
	Tier        int    `json:"tier" binding:"omitempty,min=1,max=3"`
	Status      string `json:"status" binding:"omitempty,oneof=active inactive suspended"`
}

type CustomerResponse struct {
	ID          int    `json:"id"`
	CompanyName string `json:"company_name"`
	Email       string `json:"email"`
	APIKey      string `json:"api_key,omitempty"`
	Tier        int    `json:"tier"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (h *CustomerHandler) Create(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req CreateCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.LogError(err, "Invalid customer creation request", map[string]interface{}{
			"ip": c.ClientIP(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if err := utils.ValidateEmail(req.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	if err := utils.ValidateCustomerTier(req.Tier); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	apiKey, err := utils.GenerateAPIKey()
	if err != nil {
		h.logger.LogError(err, "Failed to generate API key", nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate API key"})
		return
	}

	customer := &storage.Customer{
		CompanyName: utils.SanitizeString(req.CompanyName),
		Email:       utils.SanitizeString(req.Email),
		APIKey:      apiKey,
		Tier:        req.Tier,
		Status:      "active",
	}

	id, err := storage.CreateCustomerWithContext(ctx, h.db, customer)
	if err != nil {
		h.logger.LogError(err, "Failed to create customer", map[string]interface{}{
			"company_name": req.CompanyName,
			"email":        req.Email,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create customer"})
		return
	}

	h.logger.LogSecurityEvent("customer_created", "", c.ClientIP(), map[string]interface{}{
		"customer_id":  id,
		"company_name": req.CompanyName,
		"email":        req.Email,
		"tier":         req.Tier,
	})

	response := &CustomerResponse{
		ID:          id,
		CompanyName: customer.CompanyName,
		Email:       customer.Email,
		APIKey:      customer.APIKey,
		Tier:        customer.Tier,
		Status:      customer.Status,
		CreatedAt:   customer.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   customer.CreatedAt.Format(time.RFC3339),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *CustomerHandler) Get(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok || custID != id {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	customer, err := storage.GetCustomerWithContext(ctx, h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
			return
		}
		h.logger.LogError(err, "Failed to get customer", map[string]interface{}{
			"customer_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get customer"})
		return
	}

	response := &CustomerResponse{
		ID:          customer.ID,
		CompanyName: customer.CompanyName,
		Email:       customer.Email,
		Tier:        customer.Tier,
		Status:      customer.Status,
		CreatedAt:   customer.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   customer.UpdatedAt.Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *CustomerHandler) Update(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok || custID != id {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	var req UpdateCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	customer, err := storage.GetCustomerWithContext(ctx, h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
			return
		}
		h.logger.LogError(err, "Failed to get customer", map[string]interface{}{
			"customer_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get customer"})
		return
	}

	if req.CompanyName != "" {
		customer.CompanyName = utils.SanitizeString(req.CompanyName)
	}
	if req.Email != "" {
		if err := utils.ValidateEmail(req.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			return
		}
		customer.Email = utils.SanitizeString(req.Email)
	}
	if req.Tier != 0 {
		if err := utils.ValidateCustomerTier(req.Tier); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		customer.Tier = req.Tier
	}
	if req.Status != "" {
		customer.Status = req.Status
	}

	if err := storage.UpdateCustomerWithContext(ctx, h.db, customer); err != nil {
		h.logger.LogError(err, "Failed to update customer", map[string]interface{}{
			"customer_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update customer"})
		return
	}

	h.logger.LogSecurityEvent("customer_updated", utils.HashPrefix(customer.APIKey, 8), c.ClientIP(), map[string]interface{}{
		"customer_id": id,
		"changes":     req,
	})

	response := &CustomerResponse{
		ID:          customer.ID,
		CompanyName: customer.CompanyName,
		Email:       customer.Email,
		Tier:        customer.Tier,
		Status:      customer.Status,
		CreatedAt:   customer.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   customer.UpdatedAt.Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}