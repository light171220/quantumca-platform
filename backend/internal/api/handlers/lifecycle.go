package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/services"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type LifecycleHandler struct {
	lifecycleService *services.LifecycleService
	logger           *utils.Logger
}

func NewLifecycleHandler(lifecycleService *services.LifecycleService, logger *utils.Logger) *LifecycleHandler {
	return &LifecycleHandler{
		lifecycleService: lifecycleService,
		logger:           logger,
	}
}

type BulkRenewRequest struct {
	CertificateIDs []int `json:"certificate_ids" binding:"required"`
}

type BulkRenewResponse struct {
	Successful []int                  `json:"successful"`
	Failed     []BulkRenewFailure     `json:"failed"`
	Summary    BulkRenewSummary       `json:"summary"`
}

type BulkRenewFailure struct {
	CertificateID int    `json:"certificate_id"`
	Error         string `json:"error"`
}

type BulkRenewSummary struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

func (h *LifecycleHandler) GetStatus(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "customer_id required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer_id"})
		return
	}

	cert, err := storage.GetCertificate(h.lifecycleService.GetDB(), id)
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

	status, err := h.lifecycleService.GetCertificateStatus(cert.SerialNumber)
	if err != nil {
		h.logger.LogError(err, "Failed to get certificate status", map[string]interface{}{
			"certificate_id": id,
			"serial_number":  cert.SerialNumber,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate status"})
		return
	}

	c.JSON(http.StatusOK, status)
}

func (h *LifecycleHandler) RenewCertificate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "customer_id required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer_id"})
		return
	}

	cert, err := storage.GetCertificate(h.lifecycleService.GetDB(), id)
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

	if err := h.lifecycleService.RenewCertificate(id); err != nil {
		h.logger.LogError(err, "Failed to renew certificate", map[string]interface{}{
			"certificate_id": id,
			"customer_id":    custID,
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Certificate renewal initiated"})
}

func (h *LifecycleHandler) BulkRenew(c *gin.Context) {
	var req BulkRenewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "customer_id required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer_id"})
		return
	}

	if len(req.CertificateIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No certificate IDs provided"})
		return
	}

	if len(req.CertificateIDs) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 50 certificates can be renewed at once"})
		return
	}

	var successful []int
	var failed []BulkRenewFailure

	for _, certID := range req.CertificateIDs {
		cert, err := storage.GetCertificate(h.lifecycleService.GetDB(), certID)
		if err != nil {
			failed = append(failed, BulkRenewFailure{
				CertificateID: certID,
				Error:         "Certificate not found",
			})
			continue
		}

		if cert.CustomerID != custID {
			failed = append(failed, BulkRenewFailure{
				CertificateID: certID,
				Error:         "Access denied",
			})
			continue
		}

		if err := h.lifecycleService.RenewCertificate(certID); err != nil {
			failed = append(failed, BulkRenewFailure{
				CertificateID: certID,
				Error:         err.Error(),
			})
			continue
		}

		successful = append(successful, certID)
	}

	response := &BulkRenewResponse{
		Successful: successful,
		Failed:     failed,
		Summary: BulkRenewSummary{
			Total:      len(req.CertificateIDs),
			Successful: len(successful),
			Failed:     len(failed),
		},
	}

	h.logger.LogCertificateEvent("bulk_renewal_completed", "", custID, map[string]interface{}{
		"total_requested": len(req.CertificateIDs),
		"successful":      len(successful),
		"failed":          len(failed),
	})

	statusCode := http.StatusOK
	if len(failed) == len(req.CertificateIDs) {
		statusCode = http.StatusBadRequest
	} else if len(failed) > 0 {
		statusCode = http.StatusPartialContent
	}

	c.JSON(statusCode, response)
}