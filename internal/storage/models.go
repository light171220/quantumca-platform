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
}

type Domain struct {
	ID              int        `json:"id"`
	CustomerID      int        `json:"customer_id"`
	DomainName      string     `json:"domain_name"`
	ValidationToken string     `json:"validation_token"`
	IsVerified      bool       `json:"is_verified"`
	VerifiedAt      *time.Time `json:"verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

type Certificate struct {
	ID              int       `json:"id"`
	CustomerID      int       `json:"customer_id"`
	SerialNumber    string    `json:"serial_number"`
	CommonName      string    `json:"common_name"`
	SubjectAltNames []string  `json:"subject_alt_names"`
	CertificatePEM  string    `json:"certificate_pem"`
	PrivateKeyPEM   string    `json:"private_key_pem"`
	Algorithms      []string  `json:"algorithms"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
}

type IntermediateCA struct {
	ID             int       `json:"id"`
	CustomerID     int       `json:"customer_id"`
	CommonName     string    `json:"common_name"`
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}