package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/services"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"

	"github.com/gin-gonic/gin"
)

type BatchHandler struct {
	db             *sql.DB
	config         *utils.Config
	logger         *utils.Logger
	issuer         *ca.Issuer
	metricsService *services.MetricsService
}

func NewBatchHandler(db *sql.DB, config *utils.Config, logger *utils.Logger, metricsService *services.MetricsService) *BatchHandler {
	return &BatchHandler{
		db:             db,
		config:         config,
		logger:         logger,
		issuer:         ca.NewIssuer(config),
		metricsService: metricsService,
	}
}

type BatchCertificateIssuanceRequest struct {
	Requests []IssueCertRequest `json:"requests" binding:"required"`
	BatchID  string             `json:"batch_id"`
}

type BatchRevocationRequest struct {
	CertificateIDs []int    `json:"certificate_ids" binding:"required"`
	Reason         int      `json:"reason"`
	BatchID        string   `json:"batch_id"`
}

type BatchExportRequest struct {
	CertificateIDs []int  `json:"certificate_ids" binding:"required"`
	Format         string `json:"format" binding:"oneof=pem pkcs12 bundle"`
}

type BatchIssuanceResponse struct {
	BatchID     string                    `json:"batch_id"`
	Successful  []CertificateResponse     `json:"successful"`
	Failed      []BatchFailure            `json:"failed"`
	Summary     BatchSummary              `json:"summary"`
	Timing      map[string]time.Duration  `json:"timing"`
}

type BatchRevocationResponse struct {
	BatchID    string         `json:"batch_id"`
	Successful []int          `json:"successful"`
	Failed     []BatchFailure `json:"failed"`
	Summary    BatchSummary   `json:"summary"`
}

type BatchExportResponse struct {
	Files   map[string]string `json:"files"`
	Summary BatchSummary      `json:"summary"`
}

type BatchFailure struct {
	ID    int    `json:"id"`
	Error string `json:"error"`
}

type BatchSummary struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

type ExpiringCertificate struct {
	ID           int    `json:"id"`
	CommonName   string `json:"common_name"`
	SerialNumber string `json:"serial_number"`
	NotAfter     string `json:"not_after"`
	DaysLeft     int    `json:"days_left"`
	CustomerID   int    `json:"customer_id"`
}

type ExpiringCertificatesResponse struct {
	Certificates []ExpiringCertificate `json:"certificates"`
	Total        int                   `json:"total"`
	Page         int                   `json:"page"`
	PageSize     int                   `json:"page_size"`
	TotalPages   int                   `json:"total_pages"`
}

func (h *BatchHandler) BatchIssueCertificates(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer cancel()

	var req BatchCertificateIssuanceRequest
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

	if len(req.Requests) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No certificate requests provided"})
		return
	}

	if len(req.Requests) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 50 certificates can be issued at once"})
		return
	}

	customer, err := storage.GetCustomerWithContext(ctx, h.db, custID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	batchID := req.BatchID
	if batchID == "" {
		batchID = fmt.Sprintf("batch-%d-%d", custID, time.Now().Unix())
	}

	var caRequests []ca.CertificateRequest
	for _, certReq := range req.Requests {
		caRequest := &ca.CertificateRequest{
			CommonName:      utils.SanitizeString(certReq.CommonName),
			SubjectAltNames: h.sanitizeSubjectAltNames(certReq.SubjectAltNames),
			ValidityDays:    certReq.ValidityDays,
			Customer:        customer,
			Algorithm:       certReq.Algorithm,
			TemplateID:      certReq.TemplateID,
			UseMultiPQC:     certReq.UseMultiPQC,
			KEMAlgorithm:    certReq.KEMAlgorithm,
		}
		caRequests = append(caRequests, *caRequest)
	}

	batchReq := &ca.BatchCertificateRequest{
		Requests: caRequests,
		BatchID:  batchID,
		Timeout:  5 * time.Minute,
	}

	batchResp, err := h.issuer.IssueCertificatesBatch(batchReq)
	if err != nil {
		h.logger.LogError(err, "Batch certificate issuance failed", map[string]interface{}{
			"customer_id": custID,
			"batch_id":    batchID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Batch issuance failed"})
		return
	}

	var successful []CertificateResponse
	var failed []BatchFailure

	for i, resp := range batchResp.Responses {
		if batchResp.Errors[i] != nil {
			failed = append(failed, BatchFailure{
				ID:    i,
				Error: batchResp.Errors[i].Error(),
			})
			continue
		}

		certID, err := h.storeCertificate(ctx, custID, &req.Requests[i], &resp)
		if err != nil {
			failed = append(failed, BatchFailure{
				ID:    i,
				Error: err.Error(),
			})
			continue
		}

		certResponse := h.buildCertificateResponse(certID, &req.Requests[i], &resp)
		successful = append(successful, *certResponse)
	}

	response := &BatchIssuanceResponse{
		BatchID:    batchID,
		Successful: successful,
		Failed:     failed,
		Summary: BatchSummary{
			Total:      len(req.Requests),
			Successful: len(successful),
			Failed:     len(failed),
		},
		Timing: batchResp.Timing,
	}

	if h.metricsService != nil {
		h.metricsService.RecordBatchOperation("issuance", len(successful), len(failed))
	}

	h.logger.LogCertificateEvent("batch_issuance_completed", batchID, custID, map[string]interface{}{
		"total_requested": len(req.Requests),
		"successful":      len(successful),
		"failed":          len(failed),
	})

	statusCode := http.StatusOK
	if len(failed) == len(req.Requests) {
		statusCode = http.StatusBadRequest
	} else if len(failed) > 0 {
		statusCode = http.StatusPartialContent
	}

	c.JSON(statusCode, response)
}

func (h *BatchHandler) BatchRevokeCertificates(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	var req BatchRevocationRequest
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

	if len(req.CertificateIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No certificate IDs provided"})
		return
	}

	if len(req.CertificateIDs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 100 certificates can be revoked at once"})
		return
	}

	batchID := req.BatchID
	if batchID == "" {
		batchID = fmt.Sprintf("revoke-batch-%d-%d", custID, time.Now().Unix())
	}

	var successful []int
	var failed []BatchFailure

	for _, certID := range req.CertificateIDs {
		cert, err := storage.GetCertificateWithContext(ctx, h.db, certID)
		if err != nil {
			failed = append(failed, BatchFailure{
				ID:    certID,
				Error: "Certificate not found",
			})
			continue
		}

		if cert.CustomerID != custID {
			failed = append(failed, BatchFailure{
				ID:    certID,
				Error: "Access denied",
			})
			continue
		}

		if cert.Status != "active" {
			failed = append(failed, BatchFailure{
				ID:    certID,
				Error: "Certificate is not active",
			})
			continue
		}

		if err := storage.RevokeCertificateWithContext(ctx, h.db, certID); err != nil {
			failed = append(failed, BatchFailure{
				ID:    certID,
				Error: err.Error(),
			})
			continue
		}

		successful = append(successful, certID)
	}

	response := &BatchRevocationResponse{
		BatchID:    batchID,
		Successful: successful,
		Failed:     failed,
		Summary: BatchSummary{
			Total:      len(req.CertificateIDs),
			Successful: len(successful),
			Failed:     len(failed),
		},
	}

	if h.metricsService != nil {
		h.metricsService.RecordBatchOperation("revocation", len(successful), len(failed))
	}

	h.logger.LogCertificateEvent("batch_revocation_completed", batchID, custID, map[string]interface{}{
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

func (h *BatchHandler) GetExpiringCertificates(c *gin.Context) {
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

	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	page := 1
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 50
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	expiringCerts, total, err := h.getExpiringCertificates(ctx, custID, days, page, pageSize)
	if err != nil {
		h.logger.LogError(err, "Failed to get expiring certificates", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get expiring certificates"})
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	response := &ExpiringCertificatesResponse{
		Certificates: expiringCerts,
		Total:        total,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func (h *BatchHandler) BulkExportCertificates(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	var req BatchExportRequest
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

	if len(req.CertificateIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No certificate IDs provided"})
		return
	}

	if len(req.CertificateIDs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 100 certificates can be exported at once"})
		return
	}

	if req.Format == "" {
		req.Format = "pem"
	}

	files := make(map[string]string)
	successful := 0
	failed := 0

	for _, certID := range req.CertificateIDs {
		cert, err := storage.GetCertificateWithContext(ctx, h.db, certID)
		if err != nil {
			failed++
			continue
		}

		if cert.CustomerID != custID {
			failed++
			continue
		}

		filename := fmt.Sprintf("%s_%d", utils.SanitizeFilename(cert.CommonName), certID)
		
		switch req.Format {
		case "pem":
			files[filename+".pem"] = cert.CertificatePEM
			files[filename+"_key.pem"] = cert.PrivateKeyPEM
		case "pkcs12":
			pkcs12Data, err := h.createPKCS12Export(cert)
			if err == nil {
				files[filename+".p12"] = string(pkcs12Data)
			}
		case "bundle":
			bundle := cert.CertificatePEM + "\n" + cert.PrivateKeyPEM
			files[filename+"_bundle.pem"] = bundle
		default:
			files[filename+".pem"] = cert.CertificatePEM
		}
		
		successful++
	}

	response := &BatchExportResponse{
		Files: files,
		Summary: BatchSummary{
			Total:      len(req.CertificateIDs),
			Successful: successful,
			Failed:     failed,
		},
	}

	c.JSON(http.StatusOK, response)
}

func (h *BatchHandler) getExpiringCertificates(ctx context.Context, customerID, days, page, pageSize int) ([]ExpiringCertificate, int, error) {
	offset := (page - 1) * pageSize
	expiryDate := time.Now().AddDate(0, 0, days)
	
	countQuery := `SELECT COUNT(*) FROM certificates 
				   WHERE customer_id = ? AND status = 'active' AND not_after <= ?`
	var total int
	err := h.db.QueryRowContext(ctx, countQuery, customerID, expiryDate).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `SELECT id, common_name, serial_number, not_after, customer_id 
			  FROM certificates 
			  WHERE customer_id = ? AND status = 'active' AND not_after <= ?
			  ORDER BY not_after ASC 
			  LIMIT ? OFFSET ?`
	
	rows, err := h.db.QueryContext(ctx, query, customerID, expiryDate, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var certificates []ExpiringCertificate
	for rows.Next() {
		var cert ExpiringCertificate
		var notAfter time.Time
		
		err := rows.Scan(&cert.ID, &cert.CommonName, &cert.SerialNumber, &notAfter, &cert.CustomerID)
		if err != nil {
			continue
		}
		
		cert.NotAfter = notAfter.Format(time.RFC3339)
		cert.DaysLeft = int(time.Until(notAfter).Hours() / 24)
		
		certificates = append(certificates, cert)
	}

	return certificates, total, nil
}

func (h *BatchHandler) storeCertificate(ctx context.Context, customerID int, req *IssueCertRequest, resp *ca.CertificateResponse) (int, error) {
	cert := &storage.Certificate{
		CustomerID:           customerID,
		SerialNumber:         resp.SerialNumber,
		CommonName:           utils.SanitizeString(req.CommonName),
		SubjectAltNames:      h.sanitizeSubjectAltNames(req.SubjectAltNames),
		CertificatePEM:       resp.CertificatePEM,
		PrivateKeyPEM:        resp.PrivateKeyPEM,
		Algorithms:           resp.Algorithms,
		IsMultiPQC:          resp.IsMultiPQC,
		HasKEM:              resp.HasKEM,
		MultiPQCCertificates: resp.MultiPQCCertificates,
		MultiPQCPrivateKeys:  resp.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     resp.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    resp.KEMPrivateKeyPEM,
		Fingerprint:         resp.Fingerprint,
		KeyID:               resp.KeyID,
		NotBefore:           resp.NotBefore,
		NotAfter:            resp.NotAfter,
		Status:              "active",
	}
	
	return storage.CreateCertificateWithContext(ctx, h.db, cert)
}

func (h *BatchHandler) buildCertificateResponse(certID int, req *IssueCertRequest, resp *ca.CertificateResponse) *CertificateResponse {
	return &CertificateResponse{
		ID:                   certID,
		SerialNumber:         resp.SerialNumber,
		CommonName:           req.CommonName,
		SubjectAltNames:      req.SubjectAltNames,
		Certificate:          resp.CertificatePEM,
		PrivateKey:           resp.PrivateKeyPEM,
		Algorithms:           resp.Algorithms,
		IsMultiPQC:          resp.IsMultiPQC,
		HasKEM:              resp.HasKEM,
		MultiPQCCertificates: resp.MultiPQCCertificates,
		MultiPQCPrivateKeys:  resp.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     resp.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    resp.KEMPrivateKeyPEM,
		Fingerprint:         resp.Fingerprint,
		KeyID:               resp.KeyID,
		NotBefore:           resp.NotBefore.Format(time.RFC3339),
		NotAfter:            resp.NotAfter.Format(time.RFC3339),
		Status:              "active",
		CreatedAt:           time.Now().Format(time.RFC3339),
		ExpiresIn:           req.ValidityDays,
	}
}

func (h *BatchHandler) sanitizeSubjectAltNames(sans []string) []string {
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

func (h *BatchHandler) createPKCS12Export(cert *storage.Certificate) ([]byte, error) {
	return []byte("PKCS12 export placeholder"), nil
}