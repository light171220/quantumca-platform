package services

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type LifecycleService struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
	ticker *time.Ticker
	stopCh chan struct{}
}

func NewLifecycleService(db *sql.DB, config *utils.Config, logger *utils.Logger) *LifecycleService {
	return &LifecycleService{
		db:     db,
		config: config,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

func (s *LifecycleService) GetDB() *sql.DB {
	return s.db
}

func (s *LifecycleService) Start() error {
	s.ticker = time.NewTicker(s.config.CertificateCleanupInterval)
	go func() {
		s.logger.Info("Lifecycle service started")
		for {
			select {
			case <-s.ticker.C:
				s.cleanupExpiredCertificates()
				s.sendExpirationAlerts()
			case <-s.stopCh:
				return
			}
		}
	}()
	return nil
}

func (s *LifecycleService) Stop() error {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	close(s.stopCh)
	s.logger.Info("Lifecycle service stopped")
	return nil
}

func (s *LifecycleService) cleanupExpiredCertificates() {
	query := `UPDATE certificates SET status = 'expired' 
			  WHERE status = 'active' AND not_after < ?`
	
	result, err := s.db.Exec(query, time.Now())
	if err != nil {
		s.logger.LogError(err, "Failed to cleanup expired certificates", nil)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		s.logger.Infof("Marked %d certificates as expired", rowsAffected)
	}
}

func (s *LifecycleService) sendExpirationAlerts() {
	alertThresholds := []time.Duration{
		30 * 24 * time.Hour,
		7 * 24 * time.Hour,
		24 * time.Hour,
	}

	for _, threshold := range alertThresholds {
		s.checkExpiringCertificates(threshold)
	}
}

func (s *LifecycleService) checkExpiringCertificates(threshold time.Duration) {
	alertTime := time.Now().Add(threshold)
	
	query := `SELECT id, customer_id, common_name, not_after, serial_number
			  FROM certificates 
			  WHERE status = 'active' 
			  AND not_after BETWEEN ? AND ?
			  AND last_alert_sent < ?`
	
	rows, err := s.db.Query(query, time.Now(), alertTime, time.Now().Add(-24*time.Hour))
	if err != nil {
		s.logger.LogError(err, "Failed to check expiring certificates", nil)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var certID int
		var customerID int
		var commonName string
		var notAfter time.Time
		var serialNumber string

		err := rows.Scan(&certID, &customerID, &commonName, &notAfter, &serialNumber)
		if err != nil {
			continue
		}

		daysUntilExpiry := int(time.Until(notAfter).Hours() / 24)
		
		s.logger.LogCertificateEvent("expiration_alert", fmt.Sprintf("%d", certID), customerID, map[string]interface{}{
			"common_name":        commonName,
			"serial_number":      serialNumber,
			"days_until_expiry":  daysUntilExpiry,
			"expiry_date":        notAfter,
		})

		s.updateLastAlertSent(certID)
	}
}

func (s *LifecycleService) updateLastAlertSent(certID int) {
	query := `UPDATE certificates SET last_alert_sent = ? WHERE id = ?`
	s.db.Exec(query, time.Now(), certID)
}

func (s *LifecycleService) RenewCertificate(certID int) error {
	cert, err := storage.GetCertificate(s.db, certID)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}

	if cert.Status != "active" {
		return fmt.Errorf("cannot renew non-active certificate")
	}

	block, _ := pem.Decode([]byte(cert.CertificatePEM))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	daysUntilExpiry := int(time.Until(x509Cert.NotAfter).Hours() / 24)
	if daysUntilExpiry > 30 {
		return fmt.Errorf("certificate not eligible for renewal (expires in %d days)", daysUntilExpiry)
	}

	s.logger.LogCertificateEvent("renewal_initiated", fmt.Sprintf("%d", certID), cert.CustomerID, map[string]interface{}{
		"common_name":    cert.CommonName,
		"serial_number":  cert.SerialNumber,
		"expiry_date":    x509Cert.NotAfter,
	})

	return nil
}

func (s *LifecycleService) GetCertificateStatus(serialNumber string) (*CertificateStatus, error) {
	query := `SELECT id, status, not_before, not_after, created_at 
			  FROM certificates WHERE serial_number = ?`
	
	var certID int
	var status string
	var notBefore, notAfter, createdAt time.Time

	err := s.db.QueryRow(query, serialNumber).Scan(&certID, &status, &notBefore, &notAfter, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, err
	}

	return &CertificateStatus{
		ID:        certID,
		Status:    status,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		CreatedAt: createdAt,
		IsExpired: time.Now().After(notAfter),
		DaysUntilExpiry: int(time.Until(notAfter).Hours() / 24),
	}, nil
}

type CertificateStatus struct {
	ID              int       `json:"id"`
	Status          string    `json:"status"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	CreatedAt       time.Time `json:"created_at"`
	IsExpired       bool      `json:"is_expired"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
}