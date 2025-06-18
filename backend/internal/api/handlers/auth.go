package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type AuthHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewAuthHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *AuthHandler {
	return &AuthHandler{
		db:     db,
		config: config,
		logger: logger,
	}
}

type LoginRequest struct {
	APIKey string `json:"api_key" binding:"required,min=32,max=128"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Customer  struct {
		ID          int    `json:"id"`
		CompanyName string `json:"company_name"`
		Email       string `json:"email"`
		Tier        int    `json:"tier"`
	} `json:"customer"`
}

type RefreshRequest struct {
	Token string `json:"token" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.LogSecurityEvent("invalid_login_request", "", c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	req.APIKey = strings.TrimSpace(req.APIKey)
	if len(req.APIKey) < 32 || len(req.APIKey) > 128 {
		h.logger.LogSecurityEvent("invalid_api_key_format", "", c.ClientIP(), map[string]interface{}{
			"length": len(req.APIKey),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key format"})
		return
	}

	customer, err := storage.GetCustomerByAPIKeyWithContext(ctx, h.db, req.APIKey)
	if err != nil {
		if err == sql.ErrNoRows {
			h.logger.LogSecurityEvent("invalid_api_key_attempt", "", c.ClientIP(), map[string]interface{}{
				"api_key_prefix": utils.HashPrefix(req.APIKey, 8),
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		} else {
			h.logger.LogError(err, "Database error during login", map[string]interface{}{
				"ip": c.ClientIP(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication service unavailable"})
		}
		return
	}

	if customer.Status != "active" {
		h.logger.LogSecurityEvent("inactive_account_login_attempt", utils.HashPrefix(customer.APIKey, 8), c.ClientIP(), map[string]interface{}{
			"customer_id": customer.ID,
			"status":      customer.Status,
		})
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is not active"})
		return
	}

	token, err := utils.GenerateJWT(utils.HashPrefix(customer.APIKey, 8), customer.ID, "customer", h.config.JWTSecret)
	if err != nil {
		h.logger.LogError(err, "Failed to generate JWT", map[string]interface{}{
			"customer_id": customer.ID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication service error"})
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	h.logger.LogSecurityEvent("successful_login", utils.HashPrefix(customer.APIKey, 8), c.ClientIP(), map[string]interface{}{
		"customer_id":  customer.ID,
		"company_name": customer.CompanyName,
		"tier":         customer.Tier,
	})

	response := LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	response.Customer.ID = customer.ID
	response.Customer.CompanyName = customer.CompanyName
	response.Customer.Email = customer.Email
	response.Customer.Tier = customer.Tier

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	claims, err := utils.ValidateJWT(req.Token, h.config.JWTSecret)
	if err != nil {
		h.logger.LogSecurityEvent("invalid_token_refresh_attempt", "", c.ClientIP(), map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	customer, err := storage.GetCustomerWithContext(ctx, h.db, claims.CustomerID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Customer not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	if customer.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is not active"})
		return
	}

	newToken, err := utils.GenerateJWT(claims.UserID, claims.CustomerID, claims.Role, h.config.JWTSecret)
	if err != nil {
		h.logger.LogError(err, "Failed to refresh JWT", map[string]interface{}{
			"customer_id": claims.CustomerID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	h.logger.LogSecurityEvent("token_refreshed", claims.UserID, c.ClientIP(), map[string]interface{}{
		"customer_id": claims.CustomerID,
	})

	response := LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	response.Customer.ID = customer.ID
	response.Customer.CompanyName = customer.CompanyName
	response.Customer.Email = customer.Email
	response.Customer.Tier = customer.Tier

	c.JSON(http.StatusOK, response)
}