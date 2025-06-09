package web

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type Handler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *Handler {
	return &Handler{
		db:     db,
		config: config,
		logger: logger,
	}
}

func (h *Handler) Dashboard(c *gin.Context) {
	stats, err := h.getDashboardStats()
	if err != nil {
		h.logger.Error("Failed to get dashboard stats:", err)
		stats = &DashboardStats{}
	}

	recentCertificates, err := h.getRecentCertificates(5)
	if err != nil {
		h.logger.Error("Failed to get recent certificates:", err)
		recentCertificates = []*storage.Certificate{}
	}

	systemStatus := h.getSystemStatus()

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":              "QuantumCA Dashboard",
		"stats":              stats,
		"recentCertificates": recentCertificates,
		"systemStatus":       systemStatus,
	})
}

type DashboardStats struct {
	ActiveCertificates int    `json:"active_certificates"`
	TotalCustomers     int    `json:"total_customers"`
	IntermediateCAs    int    `json:"intermediate_cas"`
	SystemUptime       string `json:"system_uptime"`
}

type SystemStatus struct {
	RootCA         bool `json:"root_ca"`
	IntermediateCA bool `json:"intermediate_ca"`
	OCSP           bool `json:"ocsp"`
	Database       bool `json:"database"`
}

func (h *Handler) getDashboardStats() (*DashboardStats, error) {
	var stats DashboardStats

	err := h.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'active'").Scan(&stats.ActiveCertificates)
	if err != nil {
		return nil, err
	}

	err = h.db.QueryRow("SELECT COUNT(*) FROM customers WHERE status = 'active'").Scan(&stats.TotalCustomers)
	if err != nil {
		return nil, err
	}

	err = h.db.QueryRow("SELECT COUNT(*) FROM intermediate_cas WHERE status = 'active'").Scan(&stats.IntermediateCAs)
	if err != nil {
		return nil, err
	}

	stats.SystemUptime = "99.9%"

	return &stats, nil
}

func (h *Handler) getRecentCertificates(limit int) ([]*storage.Certificate, error) {
	query := `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
			  certificate_pem, private_key_pem, algorithms, not_before, not_after, status, created_at 
			  FROM certificates ORDER BY created_at DESC LIMIT ?`
	
	rows, err := h.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*storage.Certificate
	for rows.Next() {
		var cert storage.Certificate
		var subjectAltNamesJSON, algorithmsJSON string
		err := rows.Scan(&cert.ID, &cert.CustomerID, &cert.SerialNumber, 
			&cert.CommonName, &subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
			&algorithmsJSON, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, &cert)
	}

	return certificates, nil
}

func (h *Handler) getSystemStatus() *SystemStatus {
	status := &SystemStatus{
		Database: true,
	}

	if err := h.db.Ping(); err != nil {
		status.Database = false
	}

	status.RootCA = h.checkFileExists(h.config.KeysPath + "/root-ca.pem")
	status.IntermediateCA = h.checkFileExists(h.config.KeysPath + "/intermediate-ca.pem")
	status.OCSP = true

	return status
}

func (h *Handler) checkFileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func (h *Handler) Certificates(c *gin.Context) {
	certificates, err := h.getAllCertificates()
	if err != nil {
		h.logger.Error("Failed to get certificates:", err)
		certificates = []*storage.Certificate{}
	}

	c.HTML(http.StatusOK, "certificates.html", gin.H{
		"title":        "Certificates",
		"certificates": certificates,
	})
}

func (h *Handler) IssueCert(c *gin.Context) {
	customers, err := h.getAllCustomers()
	if err != nil {
		h.logger.Error("Failed to get customers:", err)
		customers = []*storage.Customer{}
	}

	c.HTML(http.StatusOK, "issue-cert.html", gin.H{
		"title":     "Issue Certificate",
		"customers": customers,
	})
}

func (h *Handler) Customers(c *gin.Context) {
	customers, err := h.getAllCustomers()
	if err != nil {
		h.logger.Error("Failed to get customers:", err)
		customers = []*storage.Customer{}
	}

	c.HTML(http.StatusOK, "customers.html", gin.H{
		"title":     "Customers",
		"customers": customers,
	})
}

func (h *Handler) IntermediateCA(c *gin.Context) {
	intermediateCAs, err := h.getAllIntermediateCAs()
	if err != nil {
		h.logger.Error("Failed to get intermediate CAs:", err)
		intermediateCAs = []*storage.IntermediateCA{}
	}

	c.HTML(http.StatusOK, "intermediate-ca.html", gin.H{
		"title":           "Intermediate CAs",
		"intermediateCAs": intermediateCAs,
	})
}

func (h *Handler) getAllCustomers() ([]*storage.Customer, error) {
	query := `SELECT id, company_name, email, api_key, tier, status, created_at FROM customers ORDER BY created_at DESC`
	
	rows, err := h.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var customers []*storage.Customer
	for rows.Next() {
		var customer storage.Customer
		err := rows.Scan(&customer.ID, &customer.CompanyName, &customer.Email, 
			&customer.APIKey, &customer.Tier, &customer.Status, &customer.CreatedAt)
		if err != nil {
			return nil, err
		}
		customers = append(customers, &customer)
	}

	return customers, nil
}

func (h *Handler) getAllCertificates() ([]*storage.Certificate, error) {
	query := `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
			  certificate_pem, private_key_pem, algorithms, not_before, not_after, status, created_at 
			  FROM certificates ORDER BY created_at DESC`
	
	rows, err := h.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*storage.Certificate
	for rows.Next() {
		var cert storage.Certificate
		var subjectAltNamesJSON, algorithmsJSON string
		err := rows.Scan(&cert.ID, &cert.CustomerID, &cert.SerialNumber, 
			&cert.CommonName, &subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
			&algorithmsJSON, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, &cert)
	}

	return certificates, nil
}

func (h *Handler) getAllIntermediateCAs() ([]*storage.IntermediateCA, error) {
	query := `SELECT id, customer_id, common_name, certificate_pem, private_key_pem, 
			  not_before, not_after, status, created_at 
			  FROM intermediate_cas ORDER BY created_at DESC`
	
	rows, err := h.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var intermediateCAs []*storage.IntermediateCA
	for rows.Next() {
		var ca storage.IntermediateCA
		err := rows.Scan(&ca.ID, &ca.CustomerID, &ca.CommonName, 
			&ca.CertificatePEM, &ca.PrivateKeyPEM, &ca.NotBefore, &ca.NotAfter, &ca.Status, &ca.CreatedAt)
		if err != nil {
			return nil, err
		}
		intermediateCAs = append(intermediateCAs, &ca)
	}

	return intermediateCAs, nil
}