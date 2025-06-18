package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	createCustomerQuery = `INSERT INTO customers (company_name, email, api_key, tier, status) 
						   VALUES (?, ?, ?, ?, ?)`
	
	getCustomerQuery = `SELECT id, company_name, email, api_key, tier, status, created_at, updated_at 
						FROM customers WHERE id = ? AND status != 'deleted'`
	
	getCustomerByAPIKeyQuery = `SELECT id, company_name, email, api_key, tier, status, created_at, updated_at 
								FROM customers WHERE api_key = ? AND status = 'active'`
	
	updateCustomerQuery = `UPDATE customers SET company_name = ?, email = ?, tier = ?, status = ?, updated_at = CURRENT_TIMESTAMP 
						   WHERE id = ? AND status != 'deleted'`
	
	createDomainQuery = `INSERT INTO domains (customer_id, domain_name, validation_token) 
						 VALUES (?, ?, ?)`
	
	getDomainQuery = `SELECT id, customer_id, domain_name, validation_token, is_verified, verified_at, created_at, updated_at 
					  FROM domains WHERE id = ?`
	
	getCustomerDomainsQuery = `SELECT id, customer_id, domain_name, validation_token, is_verified, verified_at, created_at, updated_at 
							   FROM domains WHERE customer_id = ? ORDER BY created_at DESC`
	
	verifyDomainQuery = `UPDATE domains SET is_verified = TRUE, verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP 
						 WHERE id = ?`
	
	createCertificateQuery = `INSERT INTO certificates (customer_id, serial_number, common_name, subject_alt_names, 
							  certificate_pem, private_key_pem, algorithms, is_multi_pqc, has_kem,
							  multi_pqc_certificates, multi_pqc_private_keys, kem_public_key_pem, kem_private_key_pem,
							  fingerprint, key_id, not_before, not_after, status) 
							  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	getCertificateQuery = `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
						   certificate_pem, private_key_pem, algorithms, is_multi_pqc, has_kem,
						   multi_pqc_certificates, multi_pqc_private_keys, kem_public_key_pem, kem_private_key_pem,
						   fingerprint, key_id, not_before, not_after, status, 
						   created_at, updated_at, last_alert_sent, revoked_at, revocation_reason 
						   FROM certificates WHERE id = ?`
	
	getCertificateBySerialQuery = `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
								   certificate_pem, private_key_pem, algorithms, is_multi_pqc, has_kem,
								   multi_pqc_certificates, multi_pqc_private_keys, kem_public_key_pem, kem_private_key_pem,
								   fingerprint, key_id, not_before, not_after, status, 
								   created_at, updated_at, last_alert_sent, revoked_at, revocation_reason 
								   FROM certificates WHERE serial_number = ?`
	
	getCustomerCertificatesQuery = `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
									certificate_pem, private_key_pem, algorithms, is_multi_pqc, has_kem,
									multi_pqc_certificates, multi_pqc_private_keys, kem_public_key_pem, kem_private_key_pem,
									fingerprint, key_id, not_before, not_after, status, 
									created_at, updated_at, last_alert_sent, revoked_at, revocation_reason 
									FROM certificates WHERE customer_id = ? ORDER BY created_at DESC`
	
	revokeCertificateQuery = `UPDATE certificates SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP, 
							  revocation_reason = 'user_requested', updated_at = CURRENT_TIMESTAMP 
							  WHERE id = ? AND status = 'active'`
	
	createIntermediateCAQuery = `INSERT INTO intermediate_cas (customer_id, common_name, serial_number, certificate_pem, 
								 private_key_pem, algorithms, is_multi_pqc, has_kem, multi_pqc_certificates,
								 multi_pqc_private_keys, kem_public_key_pem, kem_private_key_pem, fingerprint,
								 key_id, max_path_len, not_before, not_after, status) 
								 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	getIntermediateCAQuery = `SELECT id, customer_id, common_name, serial_number, certificate_pem, private_key_pem, 
							  algorithms, is_multi_pqc, has_kem, multi_pqc_certificates, multi_pqc_private_keys,
							  kem_public_key_pem, kem_private_key_pem, fingerprint, key_id, max_path_len,
							  not_before, not_after, status, created_at, updated_at 
							  FROM intermediate_cas WHERE id = ?`
	
	getCustomerIntermediateCAsQuery = `SELECT id, customer_id, common_name, serial_number, certificate_pem, private_key_pem, 
									   algorithms, is_multi_pqc, has_kem, multi_pqc_certificates, multi_pqc_private_keys,
									   kem_public_key_pem, kem_private_key_pem, fingerprint, key_id, max_path_len,
									   not_before, not_after, status, created_at, updated_at 
									   FROM intermediate_cas WHERE customer_id = ? ORDER BY created_at DESC`
	
	createAuditLogQuery = `INSERT INTO audit_logs (user_id, customer_id, action, resource, resource_id, 
						   ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
)

func CreateCustomer(db *sql.DB, customer *Customer) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := validateCustomerInput(customer); err != nil {
		return 0, fmt.Errorf("invalid customer data: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, createCustomerQuery, 
		sanitizeString(customer.CompanyName), 
		sanitizeString(customer.Email), 
		customer.APIKey, 
		customer.Tier, 
		customer.Status)
	if err != nil {
		return 0, fmt.Errorf("failed to create customer: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get customer ID: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	customer.ID = int(id)
	customer.CreatedAt = time.Now()

	return int(id), nil
}

func CreateCustomerWithContext(ctx context.Context, db *sql.DB, customer *Customer) (int, error) {
	if err := validateCustomerInput(customer); err != nil {
		return 0, fmt.Errorf("invalid customer data: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, createCustomerQuery, 
		sanitizeString(customer.CompanyName), 
		sanitizeString(customer.Email), 
		customer.APIKey, 
		customer.Tier, 
		customer.Status)
	if err != nil {
		return 0, fmt.Errorf("failed to create customer: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get customer ID: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	customer.ID = int(id)
	customer.CreatedAt = time.Now()

	return int(id), nil
}

func GetCustomer(db *sql.DB, id int) (*Customer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if id <= 0 {
		return nil, fmt.Errorf("invalid customer ID")
	}

	var customer Customer
	err := db.QueryRowContext(ctx, getCustomerQuery, id).Scan(
		&customer.ID, &customer.CompanyName, &customer.Email, &customer.APIKey, 
		&customer.Tier, &customer.Status, &customer.CreatedAt, &customer.UpdatedAt)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("customer not found")
		}
		return nil, fmt.Errorf("failed to get customer: %w", err)
	}

	return &customer, nil
}

func GetCustomerWithContext(ctx context.Context, db *sql.DB, id int) (*Customer, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid customer ID")
	}

	var customer Customer
	err := db.QueryRowContext(ctx, getCustomerQuery, id).Scan(
		&customer.ID, &customer.CompanyName, &customer.Email, &customer.APIKey, 
		&customer.Tier, &customer.Status, &customer.CreatedAt, &customer.UpdatedAt)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("customer not found")
		}
		return nil, fmt.Errorf("failed to get customer: %w", err)
	}

	return &customer, nil
}

func GetCustomerByAPIKey(db *sql.DB, apiKey string) (*Customer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if len(apiKey) < 32 {
		return nil, fmt.Errorf("invalid API key format")
	}

	var customer Customer
	err := db.QueryRowContext(ctx, getCustomerByAPIKeyQuery, apiKey).Scan(
		&customer.ID, &customer.CompanyName, &customer.Email, &customer.APIKey, 
		&customer.Tier, &customer.Status, &customer.CreatedAt, &customer.UpdatedAt)
	
	if err != nil {
		return nil, err
	}

	return &customer, nil
}

func GetCustomerByAPIKeyWithContext(ctx context.Context, db *sql.DB, apiKey string) (*Customer, error) {
	if len(apiKey) < 32 {
		return nil, fmt.Errorf("invalid API key format")
	}

	var customer Customer
	err := db.QueryRowContext(ctx, getCustomerByAPIKeyQuery, apiKey).Scan(
		&customer.ID, &customer.CompanyName, &customer.Email, &customer.APIKey, 
		&customer.Tier, &customer.Status, &customer.CreatedAt, &customer.UpdatedAt)
	
	if err != nil {
		return nil, err
	}

	return &customer, nil
}

func UpdateCustomer(db *sql.DB, customer *Customer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := validateCustomerInput(customer); err != nil {
		return fmt.Errorf("invalid customer data: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, updateCustomerQuery, 
		sanitizeString(customer.CompanyName), 
		sanitizeString(customer.Email), 
		customer.Tier, 
		customer.Status, 
		customer.ID)
	if err != nil {
		return fmt.Errorf("failed to update customer: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("customer not found or already deleted")
	}

	return tx.Commit()
}

func UpdateCustomerWithContext(ctx context.Context, db *sql.DB, customer *Customer) error {
	if err := validateCustomerInput(customer); err != nil {
		return fmt.Errorf("invalid customer data: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, updateCustomerQuery, 
		sanitizeString(customer.CompanyName), 
		sanitizeString(customer.Email), 
		customer.Tier, 
		customer.Status, 
		customer.ID)
	if err != nil {
		return fmt.Errorf("failed to update customer: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("customer not found or already deleted")
	}

	return tx.Commit()
}

func CreateCertificateAtomic(db *sql.DB, cert *Certificate, customerID int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := validateCertificateInput(cert); err != nil {
		return 0, fmt.Errorf("invalid certificate data: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var count int
	countQuery := `SELECT COUNT(*) FROM certificates WHERE customer_id = ? AND status = 'active' FOR UPDATE`
	err = tx.QueryRowContext(ctx, countQuery, customerID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to check certificate quota: %w", err)
	}

	if count >= 1000 {
		return 0, fmt.Errorf("certificate quota exceeded")
	}

	subjectAltNamesJSON, err := json.Marshal(cert.SubjectAltNames)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal subject alt names: %w", err)
	}

	algorithmsJSON, err := json.Marshal(cert.Algorithms)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal algorithms: %w", err)
	}

	multiPQCCertsJSON, err := json.Marshal(cert.MultiPQCCertificates)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal multi-PQC certificates: %w", err)
	}

	multiPQCKeysJSON, err := json.Marshal(cert.MultiPQCPrivateKeys)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal multi-PQC private keys: %w", err)
	}
	
	result, err := tx.ExecContext(ctx, createCertificateQuery, 
		cert.CustomerID, 
		sanitizeString(cert.SerialNumber), 
		sanitizeString(cert.CommonName), 
		string(subjectAltNamesJSON), 
		cert.CertificatePEM, 
		cert.PrivateKeyPEM, 
		string(algorithmsJSON),
		cert.IsMultiPQC,
		cert.HasKEM,
		string(multiPQCCertsJSON),
		string(multiPQCKeysJSON),
		cert.KEMPublicKeyPEM,
		cert.KEMPrivateKeyPEM,
		cert.Fingerprint,
		cert.KeyID,
		cert.NotBefore, 
		cert.NotAfter, 
		cert.Status)
	if err != nil {
		return 0, fmt.Errorf("failed to create certificate: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get certificate ID: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	cert.ID = int(id)
	cert.CreatedAt = time.Now()

	return int(id), nil
}

func CreateCertificate(db *sql.DB, cert *Certificate) (int, error) {
	return CreateCertificateAtomic(db, cert, cert.CustomerID)
}

func CreateCertificateWithContext(ctx context.Context, db *sql.DB, cert *Certificate) (int, error) {
	if err := validateCertificateInput(cert); err != nil {
		return 0, fmt.Errorf("invalid certificate data: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var count int
	countQuery := `SELECT COUNT(*) FROM certificates WHERE customer_id = ? AND status = 'active' FOR UPDATE`
	err = tx.QueryRowContext(ctx, countQuery, cert.CustomerID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to check certificate quota: %w", err)
	}

	if count >= 1000 {
		return 0, fmt.Errorf("certificate quota exceeded")
	}

	subjectAltNamesJSON, err := json.Marshal(cert.SubjectAltNames)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal subject alt names: %w", err)
	}

	algorithmsJSON, err := json.Marshal(cert.Algorithms)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal algorithms: %w", err)
	}

	multiPQCCertsJSON, err := json.Marshal(cert.MultiPQCCertificates)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal multi-PQC certificates: %w", err)
	}

	multiPQCKeysJSON, err := json.Marshal(cert.MultiPQCPrivateKeys)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal multi-PQC private keys: %w", err)
	}
	
	result, err := tx.ExecContext(ctx, createCertificateQuery, 
		cert.CustomerID, 
		sanitizeString(cert.SerialNumber), 
		sanitizeString(cert.CommonName), 
		string(subjectAltNamesJSON), 
		cert.CertificatePEM, 
		cert.PrivateKeyPEM, 
		string(algorithmsJSON),
		cert.IsMultiPQC,
		cert.HasKEM,
		string(multiPQCCertsJSON),
		string(multiPQCKeysJSON),
		cert.KEMPublicKeyPEM,
		cert.KEMPrivateKeyPEM,
		cert.Fingerprint,
		cert.KeyID,
		cert.NotBefore, 
		cert.NotAfter, 
		cert.Status)
	if err != nil {
		return 0, fmt.Errorf("failed to create certificate: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get certificate ID: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	cert.ID = int(id)
	cert.CreatedAt = time.Now()

	return int(id), nil
}

func GetCertificate(db *sql.DB, id int) (*Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if id <= 0 {
		return nil, fmt.Errorf("invalid certificate ID")
	}

	var cert Certificate
	var subjectAltNamesJSON, algorithmsJSON, multiPQCCertsJSON, multiPQCKeysJSON string
	var revokedAt sql.NullTime
	var revocationReason sql.NullString
	
	err := db.QueryRowContext(ctx, getCertificateQuery, id).Scan(
		&cert.ID, &cert.CustomerID, &cert.SerialNumber, &cert.CommonName, 
		&subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
		&algorithmsJSON, &cert.IsMultiPQC, &cert.HasKEM,
		&multiPQCCertsJSON, &multiPQCKeysJSON, &cert.KEMPublicKeyPEM, &cert.KEMPrivateKeyPEM,
		&cert.Fingerprint, &cert.KeyID, &cert.NotBefore, &cert.NotAfter, &cert.Status, 
		&cert.CreatedAt, &cert.UpdatedAt, &cert.LastAlertSent, &revokedAt, &revocationReason)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if err = json.Unmarshal([]byte(subjectAltNamesJSON), &cert.SubjectAltNames); err != nil {
		cert.SubjectAltNames = []string{}
	}

	if err = json.Unmarshal([]byte(algorithmsJSON), &cert.Algorithms); err != nil {
		cert.Algorithms = []string{}
	}

	if cert.IsMultiPQC && multiPQCCertsJSON != "" {
		if err = json.Unmarshal([]byte(multiPQCCertsJSON), &cert.MultiPQCCertificates); err != nil {
			cert.MultiPQCCertificates = []string{}
		}
	}

	if cert.IsMultiPQC && multiPQCKeysJSON != "" {
		if err = json.Unmarshal([]byte(multiPQCKeysJSON), &cert.MultiPQCPrivateKeys); err != nil {
			cert.MultiPQCPrivateKeys = []string{}
		}
	}
	
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	
	if revocationReason.Valid {
		cert.RevocationReason = revocationReason.String
	}

	return &cert, nil
}

// GetCertificateBySerial - This is the missing function that was causing the error
func GetCertificateBySerial(db *sql.DB, serialNumber string) (*Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if len(strings.TrimSpace(serialNumber)) == 0 {
		return nil, fmt.Errorf("invalid serial number")
	}

	var cert Certificate
	var subjectAltNamesJSON, algorithmsJSON, multiPQCCertsJSON, multiPQCKeysJSON string
	var revokedAt sql.NullTime
	var revocationReason sql.NullString
	
	err := db.QueryRowContext(ctx, getCertificateBySerialQuery, serialNumber).Scan(
		&cert.ID, &cert.CustomerID, &cert.SerialNumber, &cert.CommonName, 
		&subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
		&algorithmsJSON, &cert.IsMultiPQC, &cert.HasKEM,
		&multiPQCCertsJSON, &multiPQCKeysJSON, &cert.KEMPublicKeyPEM, &cert.KEMPrivateKeyPEM,
		&cert.Fingerprint, &cert.KeyID, &cert.NotBefore, &cert.NotAfter, &cert.Status, 
		&cert.CreatedAt, &cert.UpdatedAt, &cert.LastAlertSent, &revokedAt, &revocationReason)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if err = json.Unmarshal([]byte(subjectAltNamesJSON), &cert.SubjectAltNames); err != nil {
		cert.SubjectAltNames = []string{}
	}

	if err = json.Unmarshal([]byte(algorithmsJSON), &cert.Algorithms); err != nil {
		cert.Algorithms = []string{}
	}

	if cert.IsMultiPQC && multiPQCCertsJSON != "" {
		if err = json.Unmarshal([]byte(multiPQCCertsJSON), &cert.MultiPQCCertificates); err != nil {
			cert.MultiPQCCertificates = []string{}
		}
	}

	if cert.IsMultiPQC && multiPQCKeysJSON != "" {
		if err = json.Unmarshal([]byte(multiPQCKeysJSON), &cert.MultiPQCPrivateKeys); err != nil {
			cert.MultiPQCPrivateKeys = []string{}
		}
	}
	
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	
	if revocationReason.Valid {
		cert.RevocationReason = revocationReason.String
	}

	return &cert, nil
}

func GetCertificateWithContext(ctx context.Context, db *sql.DB, id int) (*Certificate, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid certificate ID")
	}

	var cert Certificate
	var subjectAltNamesJSON, algorithmsJSON, multiPQCCertsJSON, multiPQCKeysJSON string
	var revokedAt sql.NullTime
	var revocationReason sql.NullString
	
	err := db.QueryRowContext(ctx, getCertificateQuery, id).Scan(
		&cert.ID, &cert.CustomerID, &cert.SerialNumber, &cert.CommonName, 
		&subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
		&algorithmsJSON, &cert.IsMultiPQC, &cert.HasKEM,
		&multiPQCCertsJSON, &multiPQCKeysJSON, &cert.KEMPublicKeyPEM, &cert.KEMPrivateKeyPEM,
		&cert.Fingerprint, &cert.KeyID, &cert.NotBefore, &cert.NotAfter, &cert.Status, 
		&cert.CreatedAt, &cert.UpdatedAt, &cert.LastAlertSent, &revokedAt, &revocationReason)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if err = json.Unmarshal([]byte(subjectAltNamesJSON), &cert.SubjectAltNames); err != nil {
		cert.SubjectAltNames = []string{}
	}

	if err = json.Unmarshal([]byte(algorithmsJSON), &cert.Algorithms); err != nil {
		cert.Algorithms = []string{}
	}

	if cert.IsMultiPQC && multiPQCCertsJSON != "" {
		if err = json.Unmarshal([]byte(multiPQCCertsJSON), &cert.MultiPQCCertificates); err != nil {
			cert.MultiPQCCertificates = []string{}
		}
	}

	if cert.IsMultiPQC && multiPQCKeysJSON != "" {
		if err = json.Unmarshal([]byte(multiPQCKeysJSON), &cert.MultiPQCPrivateKeys); err != nil {
			cert.MultiPQCPrivateKeys = []string{}
		}
	}
	
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	
	if revocationReason.Valid {
		cert.RevocationReason = revocationReason.String
	}

	return &cert, nil
}

func CreateDomain(db *sql.DB, domain *Domain) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := validateDomainInput(domain); err != nil {
		return 0, fmt.Errorf("invalid domain data: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, createDomainQuery, 
		domain.CustomerID, 
		sanitizeString(domain.DomainName), 
		domain.ValidationToken)
	if err != nil {
		return 0, fmt.Errorf("failed to create domain: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get domain ID: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	domain.ID = int(id)
	domain.CreatedAt = time.Now()

	return int(id), nil
}

func GetDomain(db *sql.DB, id int) (*Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if id <= 0 {
		return nil, fmt.Errorf("invalid domain ID")
	}

	var domain Domain
	var verifiedAt sql.NullTime
	err := db.QueryRowContext(ctx, getDomainQuery, id).Scan(
		&domain.ID, &domain.CustomerID, &domain.DomainName, &domain.ValidationToken, 
		&domain.IsVerified, &verifiedAt, &domain.CreatedAt, &domain.UpdatedAt)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("domain not found")
		}
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}

	if verifiedAt.Valid {
		domain.VerifiedAt = &verifiedAt.Time
	}

	return &domain, nil
}

func GetCustomerDomainsWithContext(ctx context.Context, db *sql.DB, customerID int) ([]*Domain, error) {
	if customerID <= 0 {
		return nil, fmt.Errorf("invalid customer ID")
	}

	rows, err := db.QueryContext(ctx, getCustomerDomainsQuery, customerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get customer domains: %w", err)
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		var domain Domain
		var verifiedAt sql.NullTime
		err := rows.Scan(&domain.ID, &domain.CustomerID, &domain.DomainName, 
			&domain.ValidationToken, &domain.IsVerified, &verifiedAt, 
			&domain.CreatedAt, &domain.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan domain: %w", err)
		}

		if verifiedAt.Valid {
			domain.VerifiedAt = &verifiedAt.Time
		}

		domains = append(domains, &domain)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return domains, nil
}

func VerifyDomain(db *sql.DB, id int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if id <= 0 {
		return fmt.Errorf("invalid domain ID")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, verifyDomainQuery, id)
	if err != nil {
		return fmt.Errorf("failed to verify domain: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("domain not found")
	}

	return tx.Commit()
}

func RevokeCertificateWithContext(ctx context.Context, db *sql.DB, id int) error {
	if id <= 0 {
		return fmt.Errorf("invalid certificate ID")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, revokeCertificateQuery, id)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("certificate not found or already revoked")
	}

	return tx.Commit()
}

func CreateAuditLog(db *sql.DB, log *AuditLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := validateAuditLogInput(log); err != nil {
		return fmt.Errorf("invalid audit log data: %w", err)
	}

	detailsJSON, err := json.Marshal(log.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	_, err = db.ExecContext(ctx, createAuditLogQuery, 
		sanitizeString(log.UserID), 
		log.CustomerID, 
		sanitizeString(log.Action), 
		sanitizeString(log.Resource), 
		sanitizeString(log.ResourceID), 
		sanitizeString(log.IPAddress), 
		sanitizeString(log.UserAgent), 
		string(detailsJSON))
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

func validateCustomerInput(customer *Customer) error {
	if customer == nil {
		return fmt.Errorf("customer cannot be nil")
	}
	
	if len(strings.TrimSpace(customer.CompanyName)) == 0 {
		return fmt.Errorf("company name cannot be empty")
	}
	
	if len(customer.CompanyName) > 255 {
		return fmt.Errorf("company name too long")
	}
	
	if len(strings.TrimSpace(customer.Email)) == 0 {
		return fmt.Errorf("email cannot be empty")
	}
	
	if len(customer.Email) > 320 {
		return fmt.Errorf("email too long")
	}
	
	if customer.Tier < 1 || customer.Tier > 3 {
		return fmt.Errorf("invalid tier")
	}
	
	validStatuses := []string{"active", "inactive", "suspended", "deleted"}
	validStatus := false
	for _, status := range validStatuses {
		if customer.Status == status {
			validStatus = true
			break
		}
	}
	if !validStatus {
		return fmt.Errorf("invalid status")
	}
	
	return nil
}

func validateDomainInput(domain *Domain) error {
	if domain == nil {
		return fmt.Errorf("domain cannot be nil")
	}
	
	if domain.CustomerID <= 0 {
		return fmt.Errorf("invalid customer ID")
	}
	
	if len(strings.TrimSpace(domain.DomainName)) == 0 {
		return fmt.Errorf("domain name cannot be empty")
	}
	
	if len(domain.DomainName) > 253 {
		return fmt.Errorf("domain name too long")
	}
	
	if len(domain.ValidationToken) < 16 {
		return fmt.Errorf("validation token too short")
	}
	
	return nil
}

func validateCertificateInput(cert *Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}
	
	if cert.CustomerID <= 0 {
		return fmt.Errorf("invalid customer ID")
	}
	
	if len(strings.TrimSpace(cert.SerialNumber)) == 0 {
		return fmt.Errorf("serial number cannot be empty")
	}
	
	if len(strings.TrimSpace(cert.CommonName)) == 0 {
		return fmt.Errorf("common name cannot be empty")
	}
	
	if len(cert.CommonName) > 64 {
		return fmt.Errorf("common name too long")
	}
	
	if len(cert.CertificatePEM) == 0 {
		return fmt.Errorf("certificate PEM cannot be empty")
	}
	
	if len(cert.PrivateKeyPEM) == 0 {
		return fmt.Errorf("private key PEM cannot be empty")
	}
	
	if cert.NotAfter.Before(cert.NotBefore) {
		return fmt.Errorf("invalid certificate validity period")
	}
	
	validStatuses := []string{"active", "revoked", "expired"}
	validStatus := false
	for _, status := range validStatuses {
		if cert.Status == status {
			validStatus = true
			break
		}
	}
	if !validStatus {
		return fmt.Errorf("invalid certificate status")
	}
	
	return nil
}

func validateAuditLogInput(log *AuditLog) error {
	if log == nil {
		return fmt.Errorf("audit log cannot be nil")
	}
	
	if len(strings.TrimSpace(log.UserID)) == 0 {
		return fmt.Errorf("user ID cannot be empty")
	}
	
	if len(strings.TrimSpace(log.Action)) == 0 {
		return fmt.Errorf("action cannot be empty")
	}
	
	if len(strings.TrimSpace(log.Resource)) == 0 {
		return fmt.Errorf("resource cannot be empty")
	}
	
	return nil
}

func sanitizeString(input string) string {
	if len(input) > 1000 {
		input = input[:1000]
	}
	
	input = strings.TrimSpace(input)
	
	for strings.Contains(input, "\x00") {
		input = strings.ReplaceAll(input, "\x00", "")
	}
	
	return input
}