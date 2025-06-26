package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type AuthHandler struct {
	db           *sql.DB
	config       *utils.Config
	logger       *utils.Logger
	refreshTokens map[string]RefreshTokenInfo
	tokenMutex   sync.RWMutex
}

type RefreshTokenInfo struct {
	CustomerID int
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

func NewAuthHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *AuthHandler {
	handler := &AuthHandler{
		db:            db,
		config:        config,
		logger:        logger,
		refreshTokens: make(map[string]RefreshTokenInfo),
	}
	
	go handler.cleanupExpiredTokens()
	return handler
}

type LoginRequest struct {
	APIKey string `json:"api_key" binding:"required,min=32,max=128"`
}

type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
	Customer     struct {
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

	refreshToken, err := utils.GenerateRandomString(64)
	if err != nil {
		h.logger.LogError(err, "Failed to generate refresh token", map[string]interface{}{
			"customer_id": customer.ID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication service error"})
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	refreshExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	h.tokenMutex.Lock()
	h.refreshTokens[refreshToken] = RefreshTokenInfo{
		CustomerID: customer.ID,
		IssuedAt:   time.Now(),
		ExpiresAt:  refreshExpiresAt,
	}
	h.tokenMutex.Unlock()

	h.logger.LogSecurityEvent("successful_login", utils.HashPrefix(customer.APIKey, 8), c.ClientIP(), map[string]interface{}{
		"customer_id":  customer.ID,
		"company_name": customer.CompanyName,
		"tier":         customer.Tier,
	})

	response := LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
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

	h.tokenMutex.RLock()
	tokenInfo, exists := h.refreshTokens[req.Token]
	h.tokenMutex.RUnlock()

	if !exists {
		h.logger.LogSecurityEvent("invalid_refresh_token", "", c.ClientIP(), map[string]interface{}{
			"token_prefix": utils.HashPrefix(req.Token, 8),
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	if time.Now().After(tokenInfo.ExpiresAt) {
		h.tokenMutex.Lock()
		delete(h.refreshTokens, req.Token)
		h.tokenMutex.Unlock()
		
		h.logger.LogSecurityEvent("expired_refresh_token", "", c.ClientIP(), map[string]interface{}{
			"customer_id": tokenInfo.CustomerID,
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token expired"})
		return
	}

	customer, err := storage.GetCustomerWithContext(ctx, h.db, tokenInfo.CustomerID)
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

	newToken, err := utils.GenerateJWT(utils.HashPrefix(customer.APIKey, 8), customer.ID, "customer", h.config.JWTSecret)
	if err != nil {
		h.logger.LogError(err, "Failed to refresh JWT", map[string]interface{}{
			"customer_id": customer.ID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		return
	}

	newRefreshToken, err := utils.GenerateRandomString(64)
	if err != nil {
		h.logger.LogError(err, "Failed to generate new refresh token", map[string]interface{}{
			"customer_id": customer.ID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	refreshExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	h.tokenMutex.Lock()
	delete(h.refreshTokens, req.Token)
	h.refreshTokens[newRefreshToken] = RefreshTokenInfo{
		CustomerID: customer.ID,
		IssuedAt:   time.Now(),
		ExpiresAt:  refreshExpiresAt,
	}
	h.tokenMutex.Unlock()

	h.logger.LogSecurityEvent("token_refreshed", utils.HashPrefix(customer.APIKey, 8), c.ClientIP(), map[string]interface{}{
		"customer_id": customer.ID,
	})

	response := LoginResponse{
		Token:        newToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
	}
	response.Customer.ID = customer.ID
	response.Customer.CompanyName = customer.CompanyName
	response.Customer.Email = customer.Email
	response.Customer.Tier = customer.Tier

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) cleanupExpiredTokens() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		h.tokenMutex.Lock()
		now := time.Now()
		for token, info := range h.refreshTokens {
			if now.After(info.ExpiresAt) {
				delete(h.refreshTokens, token)
			}
		}
		h.tokenMutex.Unlock()
	}
}