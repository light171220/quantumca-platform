package storage

import (
	"database/sql"
	"encoding/json"
	"time"
)

func CreateCustomer(db *sql.DB, customer *Customer) (int, error) {
	query := `INSERT INTO customers (company_name, email, api_key, tier, status) 
			  VALUES (?, ?, ?, ?, ?)`
	
	result, err := db.Exec(query, customer.CompanyName, customer.Email, customer.APIKey, customer.Tier, customer.Status)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	customer.ID = int(id)
	customer.CreatedAt = time.Now()

	return int(id), nil
}

func GetCustomer(db *sql.DB, id int) (*Customer, error) {
	query := `SELECT id, company_name, email, api_key, tier, status, created_at 
			  FROM customers WHERE id = ?`
	
	var customer Customer
	err := db.QueryRow(query, id).Scan(&customer.ID, &customer.CompanyName, &customer.Email, 
		&customer.APIKey, &customer.Tier, &customer.Status, &customer.CreatedAt)
	
	if err != nil {
		return nil, err
	}

	return &customer, nil
}

func GetCustomerByAPIKey(db *sql.DB, apiKey string) (*Customer, error) {
	query := `SELECT id, company_name, email, api_key, tier, status, created_at 
			  FROM customers WHERE api_key = ?`
	
	var customer Customer
	err := db.QueryRow(query, apiKey).Scan(&customer.ID, &customer.CompanyName, &customer.Email, 
		&customer.APIKey, &customer.Tier, &customer.Status, &customer.CreatedAt)
	
	if err != nil {
		return nil, err
	}

	return &customer, nil
}

func CreateDomain(db *sql.DB, domain *Domain) (int, error) {
	query := `INSERT INTO domains (customer_id, domain_name, validation_token) 
			  VALUES (?, ?, ?)`
	
	result, err := db.Exec(query, domain.CustomerID, domain.DomainName, domain.ValidationToken)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	domain.ID = int(id)
	domain.CreatedAt = time.Now()

	return int(id), nil
}

func GetDomain(db *sql.DB, id int) (*Domain, error) {
	query := `SELECT id, customer_id, domain_name, validation_token, is_verified, verified_at, created_at 
			  FROM domains WHERE id = ?`
	
	var domain Domain
	var verifiedAt sql.NullTime
	err := db.QueryRow(query, id).Scan(&domain.ID, &domain.CustomerID, &domain.DomainName, 
		&domain.ValidationToken, &domain.IsVerified, &verifiedAt, &domain.CreatedAt)
	
	if err != nil {
		return nil, err
	}

	if verifiedAt.Valid {
		domain.VerifiedAt = &verifiedAt.Time
	}

	return &domain, nil
}

func GetCustomerDomains(db *sql.DB, customerID int) ([]*Domain, error) {
	query := `SELECT id, customer_id, domain_name, validation_token, is_verified, verified_at, created_at 
			  FROM domains WHERE customer_id = ?`
	
	rows, err := db.Query(query, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		var domain Domain
		var verifiedAt sql.NullTime
		err := rows.Scan(&domain.ID, &domain.CustomerID, &domain.DomainName, 
			&domain.ValidationToken, &domain.IsVerified, &verifiedAt, &domain.CreatedAt)
		if err != nil {
			return nil, err
		}

		if verifiedAt.Valid {
			domain.VerifiedAt = &verifiedAt.Time
		}

		domains = append(domains, &domain)
	}

	return domains, nil
}

func VerifyDomain(db *sql.DB, id int) error {
	query := `UPDATE domains SET is_verified = TRUE, verified_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := db.Exec(query, id)
	return err
}

func CreateCertificate(db *sql.DB, cert *Certificate) (int, error) {
	subjectAltNamesJSON, _ := json.Marshal(cert.SubjectAltNames)
	algorithmsJSON, _ := json.Marshal(cert.Algorithms)
	
	query := `INSERT INTO certificates (customer_id, serial_number, common_name, subject_alt_names, 
			  certificate_pem, private_key_pem, algorithms, not_before, not_after, status) 
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	result, err := db.Exec(query, cert.CustomerID, cert.SerialNumber, cert.CommonName, 
		string(subjectAltNamesJSON), cert.CertificatePEM, cert.PrivateKeyPEM, 
		string(algorithmsJSON), cert.NotBefore, cert.NotAfter, cert.Status)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	cert.ID = int(id)
	cert.CreatedAt = time.Now()

	return int(id), nil
}

func GetCertificate(db *sql.DB, id int) (*Certificate, error) {
	query := `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
			  certificate_pem, private_key_pem, algorithms, not_before, not_after, status, created_at 
			  FROM certificates WHERE id = ?`
	
	var cert Certificate
	var subjectAltNamesJSON, algorithmsJSON string
	err := db.QueryRow(query, id).Scan(&cert.ID, &cert.CustomerID, &cert.SerialNumber, 
		&cert.CommonName, &subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
		&algorithmsJSON, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt)
	
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(subjectAltNamesJSON), &cert.SubjectAltNames)
	json.Unmarshal([]byte(algorithmsJSON), &cert.Algorithms)

	return &cert, nil
}

func GetCustomerCertificates(db *sql.DB, customerID int) ([]*Certificate, error) {
	query := `SELECT id, customer_id, serial_number, common_name, subject_alt_names, 
			  certificate_pem, private_key_pem, algorithms, not_before, not_after, status, created_at 
			  FROM certificates WHERE customer_id = ?`
	
	rows, err := db.Query(query, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*Certificate
	for rows.Next() {
		var cert Certificate
		var subjectAltNamesJSON, algorithmsJSON string
		err := rows.Scan(&cert.ID, &cert.CustomerID, &cert.SerialNumber, 
			&cert.CommonName, &subjectAltNamesJSON, &cert.CertificatePEM, &cert.PrivateKeyPEM, 
			&algorithmsJSON, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt)
		if err != nil {
			return nil, err
		}

		json.Unmarshal([]byte(subjectAltNamesJSON), &cert.SubjectAltNames)
		json.Unmarshal([]byte(algorithmsJSON), &cert.Algorithms)

		certificates = append(certificates, &cert)
	}

	return certificates, nil
}

func RevokeCertificate(db *sql.DB, id int) error {
	query := `UPDATE certificates SET status = 'revoked' WHERE id = ?`
	_, err := db.Exec(query, id)
	return err
}

func CreateIntermediateCA(db *sql.DB, ca *IntermediateCA) (int, error) {
	query := `INSERT INTO intermediate_cas (customer_id, common_name, certificate_pem, 
			  private_key_pem, not_before, not_after, status) 
			  VALUES (?, ?, ?, ?, ?, ?, ?)`
	
	result, err := db.Exec(query, ca.CustomerID, ca.CommonName, ca.CertificatePEM, 
		ca.PrivateKeyPEM, ca.NotBefore, ca.NotAfter, ca.Status)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	ca.ID = int(id)
	ca.CreatedAt = time.Now()

	return int(id), nil
}

func GetIntermediateCA(db *sql.DB, id int) (*IntermediateCA, error) {
	query := `SELECT id, customer_id, common_name, certificate_pem, private_key_pem, 
			  not_before, not_after, status, created_at 
			  FROM intermediate_cas WHERE id = ?`
	
	var ca IntermediateCA
	err := db.QueryRow(query, id).Scan(&ca.ID, &ca.CustomerID, &ca.CommonName, 
		&ca.CertificatePEM, &ca.PrivateKeyPEM, &ca.NotBefore, &ca.NotAfter, &ca.Status, &ca.CreatedAt)
	
	if err != nil {
		return nil, err
	}

	return &ca, nil
}