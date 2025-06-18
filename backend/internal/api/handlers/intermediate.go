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
	CommonName   string `json:"common_name" binding:"required,max=64"`
	Country      string `json:"country" binding:"required,len=2"`
	State        string `json:"state" binding:"required,max=64"`
	City         string `json:"city" binding:"required,max=64"`
	Organization string `json:"organization" binding:"required,max=64"`
	OrgUnit      string `json:"organizational_unit" binding:"required,max=64"`
	ValidityDays int    `json:"validity_days" binding:"omitempty,min=365,max=7300"`
	Algorithm    string `json:"algorithm" binding:"omitempty"`
	UseMultiPQC  bool   `json:"use_multi_pqc"`
	KEMAlgorithm string `json:"kem_algorithm" binding:"omitempty"`
	MaxPathLen   int    `json:"max_path_len" binding:"omitempty,min=0,max=5"`
}

type IntermediateCAResponse struct {
	ID                   int      `json:"id"`
	CommonName           string   `json:"common_name"`
	SerialNumber         string   `json:"serial_number"`
	Algorithm            string   `json:"algorithm"`
	Algorithms           []string `json:"algorithms"`
	IsMultiPQC          bool     `json:"is_multi_pqc"`
	HasKEM              bool     `json:"has_kem"`
	Certificate          string   `json:"certificate,omitempty"`
	PrivateKey           string   `json:"private_key,omitempty"`
	MultiPQCCertificates []string `json:"multi_pqc_certificates,omitempty"`
	MultiPQCPrivateKeys  []string `json:"multi_pqc_private_keys,omitempty"`
	KEMPublicKeyPEM     string   `json:"kem_public_key_pem,omitempty"`
	KEMPrivateKeyPEM    string   `json:"kem_private_key_pem,omitempty"`
	Fingerprint         string   `json:"fingerprint"`
	KeyID               string   `json:"key_id"`
	MaxPathLen          int      `json:"max_path_len"`
	NotBefore           string   `json:"not_before"`
	NotAfter            string   `json:"not_after"`
	Status              string   `json:"status"`
	CreatedAt           string   `json:"created_at"`
	CustomerID          int      `json:"customer_id"`
}

type IntermediateCAListResponse struct {
	IntermediateCAs []IntermediateCAResponse `json:"intermediate_cas"`
	Total           int                      `json:"total"`
	Page            int                      `json:"page"`
	PageSize        int                      `json:"page_size"`
	TotalPages      int                      `json:"total_pages"`
}

func (h *IntermediateHandler) Create(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	var req CreateIntermediateCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.LogError(err, "Invalid intermediate CA request", map[string]interface{}{
			"ip": c.ClientIP(),
		})
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

	if err := h.validateIntermediateCARequest(&req); err != nil {
		h.logger.LogError(err, "Intermediate CA request validation failed", map[string]interface{}{
			"customer_id": custID,
			"common_name": req.CommonName,
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.checkIntermediateCAQuota(ctx, custID); err != nil {
		h.logger.LogError(err, "Intermediate CA quota exceeded", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	intermediateCertRequest := h.buildIntermediateCARequest(&req, customer)

	intermediateCert, err := h.issuer.IssueIntermediateCA(intermediateCertRequest)
	if err != nil {
		h.logger.LogError(err, "Failed to issue intermediate CA", map[string]interface{}{
			"customer_id": custID,
			"common_name": req.CommonName,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue intermediate CA"})
		return
	}

	intermediateCAID, err := h.storeIntermediateCA(ctx, custID, &req, intermediateCert)
	if err != nil {
		h.logger.LogError(err, "Failed to store intermediate CA", map[string]interface{}{
			"customer_id":   custID,
			"serial_number": intermediateCert.SerialNumber,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store intermediate CA"})
		return
	}

	h.logIntermediateCAEvent("intermediate_ca_created", intermediateCAID, custID, &req, intermediateCert)

	if h.metricsService != nil {
		h.metricsService.RecordIntermediateCACreated(customer.Tier)
	}

	response := h.buildIntermediateCAResponse(intermediateCAID, &req, intermediateCert, custID)
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
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 20
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	status := c.Query("status")

	intermediateCAs, total, err := h.getIntermediateCAsPaginated(ctx, custID, page, pageSize, status)
	if err != nil {
		h.logger.LogError(err, "Failed to get intermediate CAs", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get intermediate CAs"})
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	response := &IntermediateCAListResponse{
		IntermediateCAs: intermediateCAs,
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

	intermediateCA, err := h.getIntermediateCAByID(ctx, id)
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

	c.JSON(http.StatusOK, intermediateCA)
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

	intermediateCA, err := h.getIntermediateCAByID(ctx, id)
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

	if err := h.revokeIntermediateCA(ctx, id); err != nil {
		h.logger.LogError(err, "Failed to revoke intermediate CA", map[string]interface{}{
			"intermediate_ca_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke intermediate CA"})
		return
	}

	h.logIntermediateCAEventRevoked("intermediate_ca_revoked", id, intermediateCA.CustomerID, map[string]interface{}{
		"common_name":   intermediateCA.CommonName,
		"serial_number": intermediateCA.SerialNumber,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Intermediate CA revoked successfully"})
}

func (h *IntermediateHandler) validateIntermediateCARequest(req *CreateIntermediateCARequest) error {
	if err := utils.ValidateCommonName(req.CommonName); err != nil {
		return fmt.Errorf("invalid common name: %w", err)
	}

	if len(req.Country) != 2 {
		return fmt.Errorf("country must be a 2-letter code")
	}

	if req.ValidityDays == 0 {
		req.ValidityDays = h.config.IntermediateCAValidityDays
	}

	if req.ValidityDays < 365 || req.ValidityDays > 7300 {
		return fmt.Errorf("validity days must be between 365 and 7300")
	}

	if req.Algorithm != "" && !h.config.IsAlgorithmAllowed(req.Algorithm) {
		return fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
	}

	if req.MaxPathLen < 0 || req.MaxPathLen > 5 {
		return fmt.Errorf("max path length must be between 0 and 5")
	}

	return nil
}

func (h *IntermediateHandler) checkIntermediateCAQuota(ctx context.Context, customerID int) error {
	query := `SELECT COUNT(*) FROM intermediate_cas WHERE customer_id = ? AND status = 'active'`
	
	var count int
	err := h.db.QueryRowContext(ctx, query, customerID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check intermediate CA quota: %w", err)
	}

	maxIntermediateCAs := 5
	if count >= maxIntermediateCAs {
		return fmt.Errorf("intermediate CA quota exceeded (%d/%d)", count, maxIntermediateCAs)
	}

	return nil
}

func (h *IntermediateHandler) buildIntermediateCARequest(req *CreateIntermediateCARequest, customer *storage.Customer) *ca.IntermediateCARequest {
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = h.config.GetDefaultAlgorithm()
	}

	useMultiPQC := req.UseMultiPQC || h.config.EnableMultiPQC || algorithm == "multi-pqc"

	validityDays := req.ValidityDays
	if validityDays == 0 {
		validityDays = h.config.IntermediateCAValidityDays
	}

	maxPathLen := req.MaxPathLen
	if maxPathLen == 0 {
		maxPathLen = 0
	}

	return &ca.IntermediateCARequest{
		CommonName:   utils.SanitizeString(req.CommonName),
		Country:      utils.SanitizeString(req.Country),
		State:        utils.SanitizeString(req.State),
		City:         utils.SanitizeString(req.City),
		Org:          utils.SanitizeString(req.Organization),
		OrgUnit:      utils.SanitizeString(req.OrgUnit),
		Customer:     customer,
		Algorithm:    algorithm,
		ValidityDays: validityDays,
		MaxPathLen:   maxPathLen,
		UseMultiPQC:  useMultiPQC,
		KEMAlgorithm: req.KEMAlgorithm,
	}
}

func (h *IntermediateHandler) storeIntermediateCA(ctx context.Context, customerID int, req *CreateIntermediateCARequest, cert *ca.CertificateResponse) (int, error) {
	query := `INSERT INTO intermediate_cas (
		customer_id, common_name, serial_number, algorithms, is_multi_pqc, has_kem,
		certificate_pem, private_key_pem, multi_pqc_certificates, multi_pqc_private_keys,
		kem_public_key_pem, kem_private_key_pem, fingerprint, key_id, max_path_len,
		not_before, not_after, status, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	multiPQCCerts := ""
	multiPQCKeys := ""
	if cert.IsMultiPQC && len(cert.MultiPQCCertificates) > 0 {
		multiPQCCerts = storage.MarshalJSON(cert.MultiPQCCertificates)
		multiPQCKeys = storage.MarshalJSON(cert.MultiPQCPrivateKeys)
	}

	algorithmsJSON := storage.MarshalJSON(cert.Algorithms)

	result, err := h.db.ExecContext(ctx, query,
		customerID,
		req.CommonName,
		cert.SerialNumber,
		algorithmsJSON,
		cert.IsMultiPQC,
		cert.HasKEM,
		cert.CertificatePEM,
		cert.PrivateKeyPEM,
		multiPQCCerts,
		multiPQCKeys,
		cert.KEMPublicKeyPEM,
		cert.KEMPrivateKeyPEM,
		cert.Fingerprint,
		cert.KeyID,
		req.MaxPathLen,
		cert.NotBefore,
		cert.NotAfter,
		"active",
		time.Now(),
		time.Now(),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to insert intermediate CA: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get intermediate CA ID: %w", err)
	}

	return int(id), nil
}

func (h *IntermediateHandler) getIntermediateCAsPaginated(ctx context.Context, customerID, page, pageSize int, status string) ([]IntermediateCAResponse, int, error) {
	offset := (page - 1) * pageSize
	
	whereClause := "WHERE customer_id = ?"
	args := []interface{}{customerID}
	
	if status != "" {
		whereClause += " AND status = ?"
		args = append(args, status)
	}

	countQuery := "SELECT COUNT(*) FROM intermediate_cas " + whereClause
	var total int
	err := h.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `SELECT id, common_name, serial_number, algorithms, is_multi_pqc, has_kem,
			  fingerprint, key_id, max_path_len, not_before, not_after, status, created_at, customer_id
			  FROM intermediate_cas ` + whereClause + `
			  ORDER BY created_at DESC 
			  LIMIT ? OFFSET ?`
	
	args = append(args, pageSize, offset)
	
	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var intermediateCAs []IntermediateCAResponse
	for rows.Next() {
		var ca IntermediateCAResponse
		var algorithmsJSON string
		var notBefore, notAfter, createdAt time.Time

		err := rows.Scan(&ca.ID, &ca.CommonName, &ca.SerialNumber,
			&algorithmsJSON, &ca.IsMultiPQC, &ca.HasKEM,
			&ca.Fingerprint, &ca.KeyID, &ca.MaxPathLen,
			&notBefore, &notAfter, &ca.Status, &createdAt, &ca.CustomerID)
		if err != nil {
			continue
		}

		if err := storage.UnmarshalJSON([]byte(algorithmsJSON), &ca.Algorithms); err != nil {
			ca.Algorithms = []string{}
		}

		if len(ca.Algorithms) > 0 {
			ca.Algorithm = ca.Algorithms[0]
		}

		ca.NotBefore = notBefore.Format(time.RFC3339)
		ca.NotAfter = notAfter.Format(time.RFC3339)
		ca.CreatedAt = createdAt.Format(time.RFC3339)

		intermediateCAs = append(intermediateCAs, ca)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, err
	}

	return intermediateCAs, total, nil
}

func (h *IntermediateHandler) getIntermediateCAByID(ctx context.Context, id int) (*IntermediateCAResponse, error) {
	query := `SELECT id, common_name, serial_number, algorithms, is_multi_pqc, has_kem,
			  certificate_pem, private_key_pem, multi_pqc_certificates, multi_pqc_private_keys,
			  kem_public_key_pem, kem_private_key_pem, fingerprint, key_id, max_path_len,
			  not_before, not_after, status, created_at, customer_id
			  FROM intermediate_cas WHERE id = ?`

	var ca IntermediateCAResponse
	var algorithmsJSON, multiPQCCertsJSON, multiPQCKeysJSON string
	var notBefore, notAfter, createdAt time.Time

	err := h.db.QueryRowContext(ctx, query, id).Scan(
		&ca.ID, &ca.CommonName, &ca.SerialNumber,
		&algorithmsJSON, &ca.IsMultiPQC, &ca.HasKEM,
		&ca.Certificate, &ca.PrivateKey,
		&multiPQCCertsJSON, &multiPQCKeysJSON,
		&ca.KEMPublicKeyPEM, &ca.KEMPrivateKeyPEM,
		&ca.Fingerprint, &ca.KeyID, &ca.MaxPathLen,
		&notBefore, &notAfter, &ca.Status, &createdAt, &ca.CustomerID)

	if err != nil {
		return nil, err
	}

	if err := storage.UnmarshalJSON([]byte(algorithmsJSON), &ca.Algorithms); err != nil {
		ca.Algorithms = []string{}
	}

	if len(ca.Algorithms) > 0 {
		ca.Algorithm = ca.Algorithms[0]
	}

	if ca.IsMultiPQC && multiPQCCertsJSON != "" {
		if err := storage.UnmarshalJSON([]byte(multiPQCCertsJSON), &ca.MultiPQCCertificates); err != nil {
			ca.MultiPQCCertificates = []string{}
		}
	}

	if ca.IsMultiPQC && multiPQCKeysJSON != "" {
		if err := storage.UnmarshalJSON([]byte(multiPQCKeysJSON), &ca.MultiPQCPrivateKeys); err != nil {
			ca.MultiPQCPrivateKeys = []string{}
		}
	}

	ca.NotBefore = notBefore.Format(time.RFC3339)
	ca.NotAfter = notAfter.Format(time.RFC3339)
	ca.CreatedAt = createdAt.Format(time.RFC3339)

	return &ca, nil
}

func (h *IntermediateHandler) revokeIntermediateCA(ctx context.Context, id int) error {
	query := `UPDATE intermediate_cas SET status = 'revoked', updated_at = ? WHERE id = ?`
	
	_, err := h.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to revoke intermediate CA: %w", err)
	}

	return nil
}

func (h *IntermediateHandler) buildIntermediateCAResponse(id int, req *CreateIntermediateCARequest, cert *ca.CertificateResponse, customerID int) *IntermediateCAResponse {
	return &IntermediateCAResponse{
		ID:                   id,
		CommonName:           req.CommonName,
		SerialNumber:         cert.SerialNumber,
		Algorithm:            cert.Algorithms[0],
		Algorithms:           cert.Algorithms,
		IsMultiPQC:          cert.IsMultiPQC,
		HasKEM:              cert.HasKEM,
		Certificate:          cert.CertificatePEM,
		PrivateKey:           cert.PrivateKeyPEM,
		MultiPQCCertificates: cert.MultiPQCCertificates,
		MultiPQCPrivateKeys:  cert.MultiPQCPrivateKeys,
		KEMPublicKeyPEM:     cert.KEMPublicKeyPEM,
		KEMPrivateKeyPEM:    cert.KEMPrivateKeyPEM,
		Fingerprint:         cert.Fingerprint,
		KeyID:               cert.KeyID,
		MaxPathLen:          req.MaxPathLen,
		NotBefore:           cert.NotBefore.Format(time.RFC3339),
		NotAfter:            cert.NotAfter.Format(time.RFC3339),
		Status:              "active",
		CreatedAt:           time.Now().Format(time.RFC3339),
		CustomerID:          customerID,
	}
}

func (h *IntermediateHandler) logIntermediateCAEvent(event string, caID int, custID int, req *CreateIntermediateCARequest, cert *ca.CertificateResponse) {
	h.logger.LogCertificateEvent(event, fmt.Sprintf("%d", caID), custID, map[string]interface{}{
		"common_name":    req.CommonName,
		"serial_number":  cert.SerialNumber,
		"validity_days":  req.ValidityDays,
		"algorithms":     cert.Algorithms,
		"is_multi_pqc":   cert.IsMultiPQC,
		"has_kem":        cert.HasKEM,
		"max_path_len":   req.MaxPathLen,
	})
}

func (h *IntermediateHandler) logIntermediateCAEventRevoked(event string, caID int, custID int, details map[string]interface{}) {
	h.logger.LogCertificateEvent(event, fmt.Sprintf("%d", caID), custID, details)
}