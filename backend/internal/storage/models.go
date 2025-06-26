package storage

import (
	"time"
)

type Customer struct {
	ID          int       `json:"id"`
	CompanyName string    `json:"company_name"`
	Email       string    `json:"email"`
	APIKey      string    `json:"api_key"`
	Tier        int       `json:"tier"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Domain struct {
	ID              int        `json:"id"`
	CustomerID      int        `json:"customer_id"`
	DomainName      string     `json:"domain_name"`
	ValidationToken string     `json:"validation_token"`
	IsVerified      bool       `json:"is_verified"`
	VerifiedAt      *time.Time `json:"verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type Certificate struct {
	ID                   int        `json:"id"`
	CustomerID           int        `json:"customer_id"`
	SerialNumber         string     `json:"serial_number"`
	CommonName           string     `json:"common_name"`
	SubjectAltNames      []string   `json:"subject_alt_names"`
	CertificatePEM       string     `json:"certificate_pem"`
	PrivateKeyPEM        string     `json:"private_key_pem"`
	Algorithms           []string   `json:"algorithms"`
	IsMultiPQC          bool       `json:"is_multi_pqc"`
	HasKEM              bool       `json:"has_kem"`
	MultiPQCCertificates []string   `json:"multi_pqc_certificates"`
	MultiPQCPrivateKeys  []string   `json:"multi_pqc_private_keys"`
	KEMPublicKeyPEM     string     `json:"kem_public_key_pem"`
	KEMPrivateKeyPEM    string     `json:"kem_private_key_pem"`
	Fingerprint         string     `json:"fingerprint"`
	KeyID               string     `json:"key_id"`
	NotBefore           time.Time  `json:"not_before"`
	NotAfter            time.Time  `json:"not_after"`
	Status              string     `json:"status"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastAlertSent       time.Time  `json:"last_alert_sent"`
	RevokedAt           *time.Time `json:"revoked_at"`
	RevocationReason    string     `json:"revocation_reason"`
}

type IntermediateCA struct {
	ID                   int       `json:"id"`
	CustomerID           int       `json:"customer_id"`
	CommonName           string    `json:"common_name"`
	SerialNumber         string    `json:"serial_number"`
	Algorithms           []string  `json:"algorithms"`
	IsMultiPQC          bool      `json:"is_multi_pqc"`
	HasKEM              bool      `json:"has_kem"`
	CertificatePEM       string    `json:"certificate_pem"`
	PrivateKeyPEM        string    `json:"private_key_pem"`
	MultiPQCCertificates []string  `json:"multi_pqc_certificates"`
	MultiPQCPrivateKeys  []string  `json:"multi_pqc_private_keys"`
	KEMPublicKeyPEM     string    `json:"kem_public_key_pem"`
	KEMPrivateKeyPEM    string    `json:"kem_private_key_pem"`
	Fingerprint         string    `json:"fingerprint"`
	KeyID               string    `json:"key_id"`
	MaxPathLen          int       `json:"max_path_len"`
	NotBefore           time.Time `json:"not_before"`
	NotAfter            time.Time `json:"not_after"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID         int                    `json:"id"`
	UserID     string                 `json:"user_id"`
	CustomerID int                    `json:"customer_id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Details    map[string]interface{} `json:"details"`
	CreatedAt  time.Time              `json:"created_at"`
}

type APIKey struct {
	ID          int        `json:"id"`
	CustomerID  int        `json:"customer_id"`
	KeyHash     string     `json:"key_hash"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	LastUsed    *time.Time `json:"last_used"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type CertificateTemplate struct {
	ID              int                    `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	KeyUsages       []string               `json:"key_usages"`
	ExtKeyUsages    []string               `json:"ext_key_usages"`
	ValidityDays    int                    `json:"validity_days"`
	MaxValidityDays int                    `json:"max_validity_days"`
	IsCA            bool                   `json:"is_ca"`
	PathLength      *int                   `json:"path_length"`
	Policies        map[string]interface{} `json:"policies"`
	Status          string                 `json:"status"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}