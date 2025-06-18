package services

import (
	"database/sql"
	"fmt"
	"time"

	"quantumca-platform/internal/ca"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type DomainService struct {
	db        *sql.DB
	validator *ca.DomainValidator
	logger    *utils.Logger
}

func NewDomainService(db *sql.DB, logger *utils.Logger) *DomainService {
	return &DomainService{
		db:        db,
		validator: ca.NewDomainValidator(),
		logger:    logger,
	}
}

func (ds *DomainService) AddDomain(customerID int, domainName string) (*storage.Domain, error) {
	if err := ds.validator.ValidateSingleSAN(domainName); err != nil {
		return nil, fmt.Errorf("invalid domain name: %w", err)
	}

	token, err := ds.validator.GenerateValidationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate validation token: %w", err)
	}

	domain := &storage.Domain{
		CustomerID:      customerID,
		DomainName:      domainName,
		ValidationToken: token,
		IsVerified:      false,
	}

	id, err := storage.CreateDomain(ds.db, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain: %w", err)
	}

	domain.ID = id
	return domain, nil
}

func (ds *DomainService) ValidateDomain(domainID int, customerID int) error {
	domain, err := storage.GetDomain(ds.db, domainID)
	if err != nil {
		return fmt.Errorf("domain not found: %w", err)
	}

	if domain.CustomerID != customerID {
		return fmt.Errorf("access denied")
	}

	if domain.IsVerified {
		return fmt.Errorf("domain already verified")
	}

	result, err := ds.validator.ValidateDomainControlActual(domain.DomainName, domain.ValidationToken)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if !result.Valid {
		return fmt.Errorf("domain validation failed: %s", result.Details)
	}

	if err := storage.VerifyDomain(ds.db, domainID); err != nil {
		return fmt.Errorf("failed to mark domain as verified: %w", err)
	}

	ds.logger.LogCertificateEvent("domain_verified", fmt.Sprintf("%d", domainID), customerID, map[string]interface{}{
		"domain_name": domain.DomainName,
		"method":      result.Method,
	})

	return nil
}

func (ds *DomainService) IsVerified(customerID int, domainName string) (bool, error) {
	query := `SELECT is_verified FROM domains 
			  WHERE customer_id = ? AND domain_name = ? 
			  ORDER BY created_at DESC LIMIT 1`

	var isVerified bool
	err := ds.db.QueryRow(query, customerID, domainName).Scan(&isVerified)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	return isVerified, nil
}

func (ds *DomainService) GetVerifiedDomains(customerID int) ([]string, error) {
	query := `SELECT domain_name FROM domains 
			  WHERE customer_id = ? AND is_verified = 1`

	rows, err := ds.db.Query(query, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

func (ds *DomainService) ValidateDomainsForCertificate(customerID int, domains []string) error {
	verifiedDomains, err := ds.GetVerifiedDomains(customerID)
	if err != nil {
		return fmt.Errorf("failed to get verified domains: %w", err)
	}

	verifiedMap := make(map[string]bool)
	for _, domain := range verifiedDomains {
		verifiedMap[domain] = true
	}

	for _, domain := range domains {
		if !ds.isDomainCovered(domain, verifiedMap) {
			return fmt.Errorf("domain not verified: %s", domain)
		}
	}

	return nil
}

func (ds *DomainService) isDomainCovered(domain string, verifiedDomains map[string]bool) bool {
	if verifiedDomains[domain] {
		return true
	}

	if domain[0] == '*' && len(domain) > 2 {
		baseDomain := domain[2:]
		return verifiedDomains[baseDomain]
	}

	parts := []byte(domain)
	for i := 0; i < len(parts); i++ {
		if parts[i] == '.' {
			wildcardDomain := "*" + string(parts[i:])
			if verifiedDomains[wildcardDomain] {
				return true
			}
			break
		}
	}

	return false
}

func (ds *DomainService) CreateDNSChallenge(customerID int, domainName string) (*ca.DNSChallenge, error) {
	if err := ds.validator.ValidateSingleSAN(domainName); err != nil {
		return nil, fmt.Errorf("invalid domain name: %w", err)
	}

	challenge, err := ds.validator.CreateDNSChallenge(domainName)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS challenge: %w", err)
	}

	domain := &storage.Domain{
		CustomerID:      customerID,
		DomainName:      domainName,
		ValidationToken: challenge.Token,
		IsVerified:      false,
	}

	_, err = storage.CreateDomain(ds.db, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to store domain challenge: %w", err)
	}

	return challenge, nil
}

func (ds *DomainService) CreateHTTPChallenge(customerID int, domainName string) (*ca.HTTPChallenge, error) {
	if err := ds.validator.ValidateSingleSAN(domainName); err != nil {
		return nil, fmt.Errorf("invalid domain name: %w", err)
	}

	challenge, err := ds.validator.CreateHTTPChallenge(domainName)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP challenge: %w", err)
	}

	domain := &storage.Domain{
		CustomerID:      customerID,
		DomainName:      domainName,
		ValidationToken: challenge.Token,
		IsVerified:      false,
	}

	_, err = storage.CreateDomain(ds.db, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to store domain challenge: %w", err)
	}

	return challenge, nil
}

func (ds *DomainService) CleanExpiredChallenges() error {
	query := `DELETE FROM domains 
			  WHERE is_verified = 0 AND created_at < ?`

	cutoff := time.Now().Add(-24 * time.Hour)
	result, err := ds.db.Exec(query, cutoff)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		ds.logger.Infof("Cleaned up %d expired domain challenges", rowsAffected)
	}

	return nil
}