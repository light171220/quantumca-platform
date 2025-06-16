package ca

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type DomainValidator struct {
	dnsTimeout time.Duration
	httpTimeout time.Duration
}

type ValidationResult struct {
	Valid   bool
	Method  string
	Details string
	Token   string
}

func NewDomainValidator() *DomainValidator {
	return &DomainValidator{
		dnsTimeout:  10 * time.Second,
		httpTimeout: 30 * time.Second,
	}
}

func (dv *DomainValidator) ValidateSubjectAltNames(sans []string) error {
	if len(sans) > 100 {
		return fmt.Errorf("too many subject alternative names (max 100)")
	}

	for _, san := range sans {
		if err := dv.ValidateSingleSAN(san); err != nil {
			return fmt.Errorf("invalid SAN '%s': %w", san, err)
		}
	}

	return nil
}

func (dv *DomainValidator) ValidateSingleSAN(san string) error {
	san = strings.TrimSpace(san)
	if len(san) == 0 {
		return fmt.Errorf("empty SAN")
	}

	if len(san) > 253 {
		return fmt.Errorf("SAN too long (max 253 characters)")
	}

	if net.ParseIP(san) != nil {
		return dv.validateIPAddress(san)
	}

	if strings.Contains(san, "@") {
		return dv.validateEmailAddress(san)
	}

	return dv.validateDomainName(san)
}

func (dv *DomainValidator) validateDomainName(domain string) error {
	if strings.HasPrefix(domain, "*.") {
		return dv.validateWildcardDomain(domain)
	}

	if !dv.isValidDomainFormat(domain) {
		return fmt.Errorf("invalid domain name format")
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("domain cannot start or end with dot")
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain must have at least two labels")
	}

	for _, label := range labels {
		if err := dv.validateDomainLabel(label); err != nil {
			return fmt.Errorf("invalid label '%s': %w", label, err)
		}
	}

	return nil
}

func (dv *DomainValidator) validateWildcardDomain(domain string) error {
	if strings.Count(domain, "*") > 1 {
		return fmt.Errorf("multiple wildcards not allowed")
	}

	if !strings.HasPrefix(domain, "*.") {
		return fmt.Errorf("wildcard must be at the beginning")
	}

	baseDomain := domain[2:]
	if strings.Contains(baseDomain, "*") {
		return fmt.Errorf("wildcard not allowed in base domain")
	}

	return dv.validateDomainName(baseDomain)
}

func (dv *DomainValidator) validateDomainLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("empty label")
	}

	if len(label) > 63 {
		return fmt.Errorf("label too long (max 63 characters)")
	}

	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return fmt.Errorf("label cannot start or end with hyphen")
	}

	labelRegex := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	if !labelRegex.MatchString(label) {
		return fmt.Errorf("label contains invalid characters")
	}

	return nil
}

func (dv *DomainValidator) validateIPAddress(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address format")
	}

	if parsed.IsLoopback() {
		return fmt.Errorf("loopback addresses not allowed")
	}

	if parsed.IsPrivate() {
		return fmt.Errorf("private IP addresses not allowed")
	}

	if parsed.IsMulticast() {
		return fmt.Errorf("multicast addresses not allowed")
	}

	return nil
}

func (dv *DomainValidator) validateEmailAddress(email string) error {
	if len(email) > 254 {
		return fmt.Errorf("email address too long")
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format")
	}

	localPart := parts[0]
	domainPart := parts[1]

	if len(localPart) > 64 {
		return fmt.Errorf("email local part too long")
	}

	return dv.validateDomainName(domainPart)
}

func (dv *DomainValidator) isValidDomainFormat(domain string) bool {
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainRegex.MatchString(domain)
}

func (dv *DomainValidator) GenerateValidationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func (dv *DomainValidator) ValidateDomainControl(domain, token string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:  false,
		Token:  token,
		Method: "dns-txt",
	}

	if err := dv.validateDomainName(domain); err != nil {
		result.Details = fmt.Sprintf("Invalid domain: %v", err)
		return result, nil
	}

	if err := dv.validateDNSTXTRecord(domain, token); err != nil {
		result.Details = fmt.Sprintf("DNS TXT validation failed: %v", err)
		return result, nil
	}

	result.Valid = true
	result.Details = "Domain control validated via DNS TXT record"
	return result, nil
}

func (dv *DomainValidator) validateDNSTXTRecord(domain, expectedToken string) error {
	txtRecords, err := net.LookupTXT("_quantumca-challenge." + domain)
	if err != nil {
		return fmt.Errorf("failed to lookup TXT records: %w", err)
	}

	for _, record := range txtRecords {
		if record == expectedToken {
			return nil
		}
	}

	return fmt.Errorf("validation token not found in DNS TXT records")
}

func (dv *DomainValidator) SetTimeouts(dnsTimeout, httpTimeout time.Duration) {
	dv.dnsTimeout = dnsTimeout
	dv.httpTimeout = httpTimeout
}