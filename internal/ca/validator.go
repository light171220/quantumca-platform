package ca

import (
	"fmt"
	"io"
	"net/http"
	"net"
	"strings"
	"time"
)

type DomainValidator struct {
	httpClient *http.Client
}

func NewDomainValidator() *DomainValidator {
	return &DomainValidator{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (v *DomainValidator) ValidateDomain(domain, token string) (bool, error) {
	if err := v.validateDNS(domain, token); err == nil {
		return true, nil
	}

	if err := v.validateHTTP(domain, token); err == nil {
		return true, nil
	}

	return false, fmt.Errorf("domain validation failed for %s", domain)
}

func (v *DomainValidator) validateDNS(domain, token string) error {
	txtRecords, err := net.LookupTXT("_acme-challenge." + domain)
	if err != nil {
		return fmt.Errorf("DNS TXT lookup failed: %v", err)
	}

	for _, record := range txtRecords {
		if strings.TrimSpace(record) == token {
			return nil
		}
	}

	return fmt.Errorf("DNS validation token not found")
}

func (v *DomainValidator) validateHTTP(domain, token string) error {
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, token)
	
	resp, err := v.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP validation request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP validation returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP validation response: %v", err)
	}

	if strings.TrimSpace(string(body)) != token {
		return fmt.Errorf("HTTP validation token mismatch")
	}

	return nil
}

func (v *DomainValidator) GenerateValidationToken() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}