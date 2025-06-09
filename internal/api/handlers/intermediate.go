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

type IntermediateHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
	issuer *ca.Issuer
}

func NewIntermediateHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *IntermediateHandler {
	return &IntermediateHandler{
		db:     db,
		config: config,
		logger: logger,
		issuer: ca.NewIssuer(config),
	}
}

type CreateIntermediateCARequest struct {
	CustomerID  int    `json:"customer_id" binding:"required"`
	CommonName  string `json:"common_name" binding:"required"`
	Country     string `json:"country" binding:"required"`
	State       string `json:"state" binding:"required"`
	City        string `json:"city" binding:"required"`
	Org         string `json:"organization" binding:"required"`
	OrgUnit     string `json:"organizational_unit"`
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
}

func (h *IntermediateHandler) Create(c *gin.Context) {
	var req CreateIntermediateCARequest
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

	if customer.Tier < 2 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Intermediate CA service requires Tier 2 or higher"})
		return
	}

	intermediateCert, err := h.issuer.IssueIntermediateCA(&ca.IntermediateCARequest{
		CommonName: req.CommonName,
		Country:    req.Country,
		State:      req.State,
		City:       req.City,
		Org:        req.Org,
		OrgUnit:    req.OrgUnit,
		Customer:   customer,
	})
	if err != nil {
		h.logger.Error("Failed to issue intermediate CA:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue intermediate CA"})
		return
	}

	id, err := storage.CreateIntermediateCA(h.db, &storage.IntermediateCA{
		CustomerID:     req.CustomerID,
		CommonName:     req.CommonName,
		CertificatePEM: intermediateCert.CertificatePEM,
		PrivateKeyPEM:  intermediateCert.PrivateKeyPEM,
		NotBefore:      intermediateCert.NotBefore,
		NotAfter:       intermediateCert.NotAfter,
		Status:         "active",
	})
	if err != nil {
		h.logger.Error("Failed to store intermediate CA:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store intermediate CA"})
		return
	}

	response := &IntermediateCAResponse{
		ID:          id,
		CustomerID:  req.CustomerID,
		CommonName:  req.CommonName,
		Certificate: intermediateCert.CertificatePEM,
		PrivateKey:  intermediateCert.PrivateKeyPEM,
		NotBefore:   intermediateCert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:    intermediateCert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Status:      "active",
	}

	c.JSON(http.StatusCreated, response)
}

func (h *IntermediateHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid intermediate CA ID"})
		return
	}

	intermediateCA, err := storage.GetIntermediateCA(h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Intermediate CA not found"})
			return
		}
		h.logger.Error("Failed to get intermediate CA:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get intermediate CA"})
		return
	}

	response := &IntermediateCAResponse{
		ID:          intermediateCA.ID,
		CustomerID:  intermediateCA.CustomerID,
		CommonName:  intermediateCA.CommonName,
		Certificate: intermediateCA.CertificatePEM,
		NotBefore:   intermediateCA.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:    intermediateCA.NotAfter.Format("2006-01-02T15:04:05Z"),
		Status:      intermediateCA.Status,
		CreatedAt:   intermediateCA.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	c.JSON(http.StatusOK, response)
}