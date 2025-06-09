package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	CustomerID int    `json:"customer_id" binding:"required"`
	DomainName string `json:"domain_name" binding:"required"`
}

type DomainResponse struct {
	ID               int    `json:"id"`
	CustomerID       int    `json:"customer_id"`
	DomainName       string `json:"domain_name"`
	ValidationToken  string `json:"validation_token"`
	IsVerified       bool   `json:"is_verified"`
	VerifiedAt       string `json:"verified_at,omitempty"`
	CreatedAt        string `json:"created_at"`
}

func (h *DomainHandler) Add(c *gin.Context) {
	var req AddDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := storage.GetCustomer(h.db, req.CustomerID)
	if err != nil {
		h.logger.Error("Failed to get customer:", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	token := uuid.New().String()

	domain := &storage.Domain{
		CustomerID:      req.CustomerID,
		DomainName:      req.DomainName,
		ValidationToken: token,
		IsVerified:      false,
	}

	id, err := storage.CreateDomain(h.db, domain)
	if err != nil {
		h.logger.Error("Failed to create domain:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create domain"})
		return
	}

	response := &DomainResponse{
		ID:              id,
		CustomerID:      domain.CustomerID,
		DomainName:      domain.DomainName,
		ValidationToken: domain.ValidationToken,
		IsVerified:      domain.IsVerified,
		CreatedAt:       domain.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *DomainHandler) Verify(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain ID"})
		return
	}

	domain, err := storage.GetDomain(h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
			return
		}
		h.logger.Error("Failed to get domain:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get domain"})
		return
	}

	if domain.IsVerified {
		c.JSON(http.StatusOK, gin.H{"message": "Domain already verified"})
		return
	}

	verified, err := h.validator.ValidateDomain(domain.DomainName, domain.ValidationToken)
	if err != nil {
		h.logger.Error("Failed to validate domain:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate domain"})
		return
	}

	if !verified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain validation failed"})
		return
	}

	if err := storage.VerifyDomain(h.db, id); err != nil {
		h.logger.Error("Failed to update domain verification:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update domain verification"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Domain verified successfully"})
}