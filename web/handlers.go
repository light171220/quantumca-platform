package web

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type Handler struct {
	db      *sql.DB
	config  *utils.Config
	logger  *utils.Logger
	issuer  *ca.Issuer
}

type DashboardData struct {
	Stats struct {
		TotalCertificates    int    `json:"total_certificates"`
		ActiveCertificates   int    `json:"active_certificates"`
		ExpiringCertificates int    `json:"expiring_certificates"`
		RevokedCertificates  int    `json:"revoked_certificates"`
		TotalCustomers       int    `json:"total_customers"`
		IntermediateCAs      int    `json:"intermediate_cas"`
		SystemUptime         string `json:"system_uptime"`
	} `json:"stats"`
	RecentCertificates []CertificateInfo `json:"recent_certificates"`
	SystemStatus       SystemStatus      `json:"system_status"`
}

type CertificateInfo struct {
	ID           int       `json:"id"`
	CommonName   string    `json:"common_name"`
	CustomerID   int       `json:"customer_id"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	NotAfter     time.Time `json:"not_after"`
	SerialNumber string    `json:"serial_number"`
	Algorithms   []string  `json:"algorithms"`
}

type CustomerInfo struct {
	ID          int       `json:"id"`
	CompanyName string    `json:"company_name"`
	Email       string    `json:"email"`
	Tier        int       `json:"tier"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type IntermediateCAInfo struct {
	ID         int       `json:"id"`
	CommonName string    `json:"common_name"`
	CustomerID int       `json:"customer_id"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	NotAfter   time.Time `json:"not_after"`
}

type SystemStatus struct {
	RootCA         bool `json:"root_ca"`
	IntermediateCA bool `json:"intermediate_ca"`
	OCSP           bool `json:"ocsp"`
	Database       bool `json:"database"`
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalPages int         `json:"total_pages"`
}

var startTime = time.Now()

func NewHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *Handler {
	return &Handler{
		db:     db,
		config: config,
		logger: logger,
		issuer: ca.NewIssuer(config),
	}
}

func (h *Handler) Dashboard(c *gin.Context) {
	data, err := h.getDashboardData()
	if err != nil {
		h.logger.LogError(err, "Failed to get dashboard data", nil)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"title": "Error",
			"error": "Failed to load dashboard data",
		})
		return
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":               "QuantumCA Dashboard",
		"stats":               data.Stats,
		"recentCertificates":  data.RecentCertificates,
		"systemStatus":        data.SystemStatus,
	})
}

func (h *Handler) Certificates(c *gin.Context) {
	page := h.getPageFromQuery(c, "page", 1)
	pageSize := h.getPageFromQuery(c, "page_size", 20)
	status := strings.TrimSpace(c.Query("status"))
	search := strings.TrimSpace(c.Query("search"))

	certificates, total, err := h.getCertificatesData(page, pageSize, status, search)
	if err != nil {
		h.logger.LogError(err, "Failed to get certificates data", map[string]interface{}{
			"page":      page,
			"page_size": pageSize,
			"status":    status,
			"search":    search,
		})
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"title": "Error",
			"error": "Failed to load certificates",
		})
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	c.HTML(http.StatusOK, "certificates.html", gin.H{
		"title":        "Certificates",
		"certificates": certificates,
		"pagination": gin.H{
			"current_page": page,
			"total_pages":  totalPages,
			"page_size":    pageSize,
			"total":        total,
		},
		"filters": gin.H{
			"status": status,
			"search": search,
		},
	})
}

func (h *Handler) IssueCert(c *gin.Context) {
	if c.Request.Method == "GET" {
		customers, err := h.getActiveCustomers()
		if err != nil {
			h.logger.LogError(err, "Failed to get customers for cert issuance", nil)
			customers = []CustomerInfo{}
		}

		c.HTML(http.StatusOK, "issue-cert.html", gin.H{
			"title":     "Issue Certificate",
			"customers": customers,
		})
		return
	}

	if c.Request.Method == "POST" {
		h.handleCertificateIssuance(c)
		return
	}

	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
}

func (h *Handler) Customers(c *gin.Context) {
	page := h.getPageFromQuery(c, "page", 1)
	pageSize := h.getPageFromQuery(c, "page_size", 20)
	status := strings.TrimSpace(c.Query("status"))
	search := strings.TrimSpace(c.Query("search"))

	customers, total, err := h.getCustomersData(page, pageSize, status, search)
	if err != nil {
		h.logger.LogError(err, "Failed to get customers data", map[string]interface{}{
			"page":      page,
			"page_size": pageSize,
			"status":    status,
			"search":    search,
		})
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"title": "Error",
			"error": "Failed to load customers",
		})
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	c.HTML(http.StatusOK, "customers.html", gin.H{
		"title":     "Customers",
		"customers": customers,
		"pagination": gin.H{
			"current_page": page,
			"total_pages":  totalPages,
			"page_size":    pageSize,
			"total":        total,
		},
		"filters": gin.H{
			"status": status,
			"search": search,
		},
	})
}

func (h *Handler) IntermediateCA(c *gin.Context) {
	page := h.getPageFromQuery(c, "page", 1)
	pageSize := h.getPageFromQuery(c, "page_size", 20)

	intermediateCAs, total, err := h.getIntermediateCAData(page, pageSize)
	if err != nil {
		h.logger.LogError(err, "Failed to get intermediate CA data", map[string]interface{}{
			"page":      page,
			"page_size": pageSize,
		})
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"title": "Error",
			"error": "Failed to load intermediate CAs",
		})
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	c.HTML(http.StatusOK, "intermediate-ca.html", gin.H{
		"title":           "Intermediate CAs",
		"intermediateCAs": intermediateCAs,
		"pagination": gin.H{
			"current_page": page,
			"total_pages":  totalPages,
			"page_size":    pageSize,
			"total":        total,
		},
	})
}

func (h *Handler) getDashboardData() (*DashboardData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data := &DashboardData{}

	queries := map[string]*int{
		"SELECT COUNT(*) FROM certificates":                                          &data.Stats.TotalCertificates,
		"SELECT COUNT(*) FROM certificates WHERE status = 'active'":                 &data.Stats.ActiveCertificates,
		"SELECT COUNT(*) FROM certificates WHERE status = 'revoked'":                &data.Stats.RevokedCertificates,
		"SELECT COUNT(*) FROM customers WHERE status = 'active'":                    &data.Stats.TotalCustomers,
		"SELECT COUNT(*) FROM intermediate_cas WHERE status = 'active'":             &data.Stats.IntermediateCAs,
	}

	for query, target := range queries {
		if err := h.db.QueryRowContext(ctx, query).Scan(target); err != nil {
			h.logger.LogError(err, "Failed to execute dashboard query", map[string]interface{}{
				"query": query,
			})
			*target = 0
		}
	}

	expiryThreshold := time.Now().AddDate(0, 0, 30)
	expiryQuery := "SELECT COUNT(*) FROM certificates WHERE status = 'active' AND not_after < ?"
	if err := h.db.QueryRowContext(ctx, expiryQuery, expiryThreshold).Scan(&data.Stats.ExpiringCertificates); err != nil {
		h.logger.LogError(err, "Failed to get expiring certificates count", nil)
		data.Stats.ExpiringCertificates = 0
	}

	data.Stats.SystemUptime = time.Since(startTime).Truncate(time.Second).String()

	recentCerts, err := h.getRecentCertificates(5)
	if err != nil {
		h.logger.LogError(err, "Failed to get recent certificates", nil)
		recentCerts = []CertificateInfo{}
	}
	data.RecentCertificates = recentCerts

	data.SystemStatus = h.getSystemStatus()

	return data, nil
}

func (h *Handler) getCertificatesData(page, pageSize int, status, search string) ([]CertificateInfo, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	offset := (page - 1) * pageSize
	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if status != "" && h.isValidStatus(status) {
		whereClause += " AND status = ?"
		args = append(args, status)
	}

	if search != "" {
		whereClause += " AND (common_name LIKE ? OR serial_number LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM certificates " + whereClause
	if err := h.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, customer_id, serial_number, common_name, status, 
			  not_before, not_after, created_at, subject_alt_names, algorithms 
			  FROM certificates ` + whereClause + ` 
			  ORDER BY created_at DESC LIMIT ? OFFSET ?`

	args = append(args, pageSize, offset)
	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var certificates []CertificateInfo
	for rows.Next() {
		var cert CertificateInfo
		var algorithmsJSON, subjectAltNamesJSON string
		var notBefore time.Time

		err := rows.Scan(&cert.ID, &cert.CustomerID, &cert.SerialNumber,
			&cert.CommonName, &cert.Status, &notBefore, &cert.NotAfter,
			&cert.CreatedAt, &subjectAltNamesJSON, &algorithmsJSON)
		if err != nil {
			continue
		}

		if err := storage.UnmarshalJSON([]byte(algorithmsJSON), &cert.Algorithms); err != nil {
			cert.Algorithms = []string{"unknown"}
		}

		certificates = append(certificates, cert)
	}

	return certificates, total, rows.Err()
}

func (h *Handler) getCustomersData(page, pageSize int, status, search string) ([]CustomerInfo, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	offset := (page - 1) * pageSize
	whereClause := "WHERE status != 'deleted'"
	args := []interface{}{}

	if status != "" && h.isValidCustomerStatus(status) {
		whereClause += " AND status = ?"
		args = append(args, status)
	}

	if search != "" {
		whereClause += " AND (company_name LIKE ? OR email LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM customers " + whereClause
	if err := h.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, company_name, email, tier, status, created_at, updated_at 
			  FROM customers ` + whereClause + ` 
			  ORDER BY created_at DESC LIMIT ? OFFSET ?`

	args = append(args, pageSize, offset)
	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var customers []CustomerInfo
	for rows.Next() {
		var customer CustomerInfo
		err := rows.Scan(&customer.ID, &customer.CompanyName, &customer.Email,
			&customer.Tier, &customer.Status, &customer.CreatedAt, &customer.UpdatedAt)
		if err != nil {
			continue
		}
		customers = append(customers, customer)
	}

	return customers, total, rows.Err()
}

func (h *Handler) getIntermediateCAData(page, pageSize int) ([]IntermediateCAInfo, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	offset := (page - 1) * pageSize

	var total int
	countQuery := "SELECT COUNT(*) FROM intermediate_cas"
	if err := h.db.QueryRowContext(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, customer_id, common_name, status, not_after, created_at 
			  FROM intermediate_cas 
			  ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := h.db.QueryContext(ctx, query, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var intermediateCAs []IntermediateCAInfo
	for rows.Next() {
		var ca IntermediateCAInfo
		err := rows.Scan(&ca.ID, &ca.CustomerID, &ca.CommonName,
			&ca.Status, &ca.NotAfter, &ca.CreatedAt)
		if err != nil {
			continue
		}
		intermediateCAs = append(intermediateCAs, ca)
	}

	return intermediateCAs, total, rows.Err()
}

func (h *Handler) getRecentCertificates(limit int) ([]CertificateInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT id, customer_id, serial_number, common_name, status, 
			  not_after, created_at, algorithms 
			  FROM certificates ORDER BY created_at DESC LIMIT ?`

	rows, err := h.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []CertificateInfo
	for rows.Next() {
		var cert CertificateInfo
		var algorithmsJSON string

		err := rows.Scan(&cert.ID, &cert.CustomerID, &cert.SerialNumber,
			&cert.CommonName, &cert.Status, &cert.NotAfter, &cert.CreatedAt, &algorithmsJSON)
		if err != nil {
			continue
		}

		if err := storage.UnmarshalJSON([]byte(algorithmsJSON), &cert.Algorithms); err != nil {
			cert.Algorithms = []string{"unknown"}
		}

		certificates = append(certificates, cert)
	}

	return certificates, rows.Err()
}

func (h *Handler) getActiveCustomers() ([]CustomerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT id, company_name, email, tier FROM customers 
			  WHERE status = 'active' ORDER BY company_name`

	rows, err := h.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var customers []CustomerInfo
	for rows.Next() {
		var customer CustomerInfo
		err := rows.Scan(&customer.ID, &customer.CompanyName, &customer.Email, &customer.Tier)
		if err != nil {
			continue
		}
		customers = append(customers, customer)
	}

	return customers, rows.Err()
}

func (h *Handler) handleCertificateIssuance(c *gin.Context) {
	commonName := strings.TrimSpace(c.PostForm("common_name"))
	customerIDStr := strings.TrimSpace(c.PostForm("customer_id"))
	validityDaysStr := strings.TrimSpace(c.PostForm("validity_days"))
	algorithm := strings.TrimSpace(c.PostForm("algorithm"))
	subjectAltNames := strings.TrimSpace(c.PostForm("subject_alt_names"))

	if commonName == "" || customerIDStr == "" {
		c.HTML(http.StatusBadRequest, "issue-cert.html", gin.H{
			"title": "Issue Certificate",
			"error": "Common name and customer ID are required",
		})
		return
	}

	customerID, err := strconv.Atoi(customerIDStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "issue-cert.html", gin.H{
			"title": "Issue Certificate",
			"error": "Invalid customer ID",
		})
		return
	}

	validityDays := 365
	if validityDaysStr != "" {
		if days, err := strconv.Atoi(validityDaysStr); err == nil && days > 0 && days <= 3650 {
			validityDays = days
		}
	}

	if algorithm == "" {
		algorithm = "rsa2048"
	}

	customer, err := storage.GetCustomer(h.db, customerID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "issue-cert.html", gin.H{
			"title": "Issue Certificate",
			"error": "Customer not found",
		})
		return
	}

	var sans []string
	if subjectAltNames != "" {
		sans = strings.Split(subjectAltNames, ",")
		for i, san := range sans {
			sans[i] = strings.TrimSpace(san)
		}
	}

	certRequest := &ca.CertificateRequest{
		CommonName:      commonName,
		SubjectAltNames: sans,
		ValidityDays:    validityDays,
		Customer:        customer,
		Algorithm:       algorithm,
		UseHybrid:       true,
	}

	certResponse, err := h.issuer.IssueCertificate(certRequest)
	if err != nil {
		h.logger.LogError(err, "Failed to issue certificate", map[string]interface{}{
			"customer_id": customerID,
			"common_name": commonName,
			"algorithm":   algorithm,
		})
		c.HTML(http.StatusInternalServerError, "issue-cert.html", gin.H{
			"title": "Issue Certificate",
			"error": "Failed to issue certificate: " + err.Error(),
		})
		return
	}

	cert := &storage.Certificate{
		CustomerID:      customerID,
		SerialNumber:    certResponse.SerialNumber,
		CommonName:      commonName,
		SubjectAltNames: sans,
		CertificatePEM:  certResponse.CertificatePEM,
		PrivateKeyPEM:   certResponse.PrivateKeyPEM,
		Algorithms:      certResponse.Algorithms,
		NotBefore:       certResponse.NotBefore,
		NotAfter:        certResponse.NotAfter,
		Status:          "active",
	}

	certID, err := storage.CreateCertificate(h.db, cert)
	if err != nil {
		h.logger.LogError(err, "Failed to store certificate", map[string]interface{}{
			"serial_number": certResponse.SerialNumber,
		})
		c.HTML(http.StatusInternalServerError, "issue-cert.html", gin.H{
			"title": "Issue Certificate",
			"error": "Failed to store certificate",
		})
		return
	}

	cert.ID = certID

	c.HTML(http.StatusOK, "cert-issued.html", gin.H{
		"title":       "Certificate Issued",
		"certificate": cert,
		"success":     "Certificate issued successfully",
		"isHybrid":    certResponse.IsHybrid,
	})
}

func (h *Handler) getSystemStatus() SystemStatus {
	status := SystemStatus{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.db.PingContext(ctx); err == nil {
		var count int
		if err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM customers LIMIT 1").Scan(&count); err == nil {
			status.Database = true
		}
	}

	status.RootCA = true
	status.IntermediateCA = true
	status.OCSP = true

	return status
}

func (h *Handler) getPageFromQuery(c *gin.Context, param string, defaultValue int) int {
	if pageStr := c.Query(param); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 && p <= 1000 {
			return p
		}
	}
	return defaultValue
}

func (h *Handler) isValidStatus(status string) bool {
	validStatuses := []string{"active", "revoked", "expired"}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}

func (h *Handler) isValidCustomerStatus(status string) bool {
	validStatuses := []string{"active", "inactive", "suspended"}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}