package ca

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type DomainValidator struct {
	dnsTimeout  time.Duration
	httpTimeout time.Duration
	httpClient  *http.Client
}

type ValidationResult struct {
	Valid   bool
	Method  string
	Details string
	Token   string
}

type DNSChallenge struct {
	Domain      string
	Token       string
	RecordName  string
	RecordValue string
	ExpiresAt   time.Time
}

type HTTPChallenge struct {
	Domain    string
	Token     string
	Path      string
	Content   string
	ExpiresAt time.Time
}

func NewDomainValidator() *DomainValidator {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &DomainValidator{
		dnsTimeout:  10 * time.Second,
		httpTimeout: 30 * time.Second,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
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

func (dv *DomainValidator) ValidateDomainControlActual(domain, token string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:  false,
		Token:  token,
		Method: "dns-txt",
	}

	if err := dv.validateDomainName(domain); err != nil {
		result.Details = fmt.Sprintf("Invalid domain: %v", err)
		return result, nil
	}

	dnsResult := dv.validateDNSTXTRecordActual(domain, token)
	if dnsResult.Valid {
		return dnsResult, nil
	}

	result.Method = "http-01"
	httpResult := dv.validateHTTPChallengeActual(domain, token)
	if httpResult.Valid {
		return httpResult, nil
	}

	result.Details = fmt.Sprintf("Domain validation failed - DNS: %s, HTTP: %s", dnsResult.Details, httpResult.Details)
	return result, nil
}

func (dv *DomainValidator) validateDNSTXTRecordActual(domain, expectedToken string) *ValidationResult {
	result := &ValidationResult{
		Valid:  false,
		Token:  expectedToken,
		Method: "dns-txt",
	}

	ctx, cancel := context.WithTimeout(context.Background(), dv.dnsTimeout)
	defer cancel()

	recordName := fmt.Sprintf("_quantumca-challenge.%s", domain)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: 5 * time.Second,
			}
			dnsServers := []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"}
			
			var lastErr error
			for _, server := range dnsServers {
				conn, err := dialer.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}

	txtRecords, err := resolver.LookupTXT(ctx, recordName)
	if err != nil {
		result.Details = fmt.Sprintf("DNS TXT lookup failed for %s: %v", recordName, err)
		return result
	}

	if len(txtRecords) == 0 {
		result.Details = fmt.Sprintf("No TXT records found for %s", recordName)
		return result
	}

	challengePrefix := "quantumca-domain-validation="
	for _, record := range txtRecords {
		if strings.HasPrefix(record, challengePrefix) {
			recordToken := strings.TrimPrefix(record, challengePrefix)
			if strings.TrimSpace(recordToken) == expectedToken {
				result.Valid = true
				result.Details = fmt.Sprintf("Valid TXT record found: %s", record)
				return result
			}
		}
	}

	result.Details = fmt.Sprintf("Expected token '%s' not found in TXT records: %v", expectedToken, txtRecords)
	return result
}

func (dv *DomainValidator) validateHTTPChallengeActual(domain, token string) *ValidationResult {
	result := &ValidationResult{
		Valid:  false,
		Token:  token,
		Method: "http-01",
	}

	challengePath := fmt.Sprintf("/.well-known/quantumca-challenge/%s", token)
	
	httpURLs := []string{
		fmt.Sprintf("http://%s%s", domain, challengePath),
		fmt.Sprintf("http://www.%s%s", domain, challengePath),
	}

	for _, challengeURL := range httpURLs {
		if dv.tryHTTPChallenge(challengeURL, token, result) {
			return result
		}
	}

	result.Details = fmt.Sprintf("HTTP challenge failed for all attempted URLs")
	return result
}

func (dv *DomainValidator) tryHTTPChallenge(challengeURL, token string, result *ValidationResult) bool {
	ctx, cancel := context.WithTimeout(context.Background(), dv.httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", challengeURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "QuantumCA-Domain-Validator/1.0")
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{
		Timeout: dv.httpTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return false
	}

	responseContent := strings.TrimSpace(string(body))
	expectedContent := fmt.Sprintf("quantumca-domain-validation:%s", token)
	
	if responseContent == expectedContent {
		result.Valid = true
		result.Details = fmt.Sprintf("Valid HTTP challenge response from %s", challengeURL)
		return true
	}

	return false
}

func (dv *DomainValidator) CreateDNSChallenge(domain string) (*DNSChallenge, error) {
	token, err := dv.GenerateValidationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate validation token: %w", err)
	}

	recordName := fmt.Sprintf("_quantumca-challenge.%s", domain)
	recordValue := fmt.Sprintf("quantumca-domain-validation=%s", token)

	challenge := &DNSChallenge{
		Domain:      domain,
		Token:       token,
		RecordName:  recordName,
		RecordValue: recordValue,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	return challenge, nil
}

func (dv *DomainValidator) CreateHTTPChallenge(domain string) (*HTTPChallenge, error) {
	token, err := dv.GenerateValidationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate validation token: %w", err)
	}

	path := fmt.Sprintf("/.well-known/quantumca-challenge/%s", token)
	content := fmt.Sprintf("quantumca-domain-validation:%s", token)

	challenge := &HTTPChallenge{
		Domain:    domain,
		Token:     token,
		Path:      path,
		Content:   content,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	return challenge, nil
}

func (dv *DomainValidator) ValidateWildcardDomainActual(domain, token string) (*ValidationResult, error) {
	if !strings.HasPrefix(domain, "*.") {
		return nil, fmt.Errorf("not a wildcard domain")
	}

	baseDomain := domain[2:]
	
	result := &ValidationResult{
		Valid:  false,
		Token:  token,
		Method: "dns-txt",
	}

	recordName := fmt.Sprintf("_quantumca-challenge.%s", baseDomain)
	
	ctx, cancel := context.WithTimeout(context.Background(), dv.dnsTimeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: 5 * time.Second,
			}
			dnsServers := []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"}
			
			var lastErr error
			for _, server := range dnsServers {
				conn, err := dialer.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	
	txtRecords, err := resolver.LookupTXT(ctx, recordName)
	if err != nil {
		result.Details = fmt.Sprintf("DNS TXT lookup failed for wildcard domain %s: %v", recordName, err)
		return result, nil
	}

	challengePrefix := "quantumca-domain-validation="
	for _, record := range txtRecords {
		if strings.HasPrefix(record, challengePrefix) {
			recordToken := strings.TrimPrefix(record, challengePrefix)
			if strings.TrimSpace(recordToken) == token {
				result.Valid = true
				result.Details = fmt.Sprintf("Valid wildcard DNS challenge for %s", domain)
				return result, nil
			}
		}
	}

	result.Details = fmt.Sprintf("Wildcard validation failed - token not found in DNS TXT records for %s", recordName)
	return result, nil
}

func (dv *DomainValidator) ValidateDomainOwnership(domains []string, customerID int) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains to validate")
	}

	for _, domain := range domains {
		if err := dv.validateDomainName(domain); err != nil {
			return fmt.Errorf("invalid domain %s: %w", domain, err)
		}

		token, err := dv.GenerateValidationToken()
		if err != nil {
			return fmt.Errorf("failed to generate token for domain %s: %w", domain, err)
		}

		var result *ValidationResult
		var validationErr error
		
		if strings.HasPrefix(domain, "*.") {
			result, validationErr = dv.ValidateWildcardDomainActual(domain, token)
		} else {
			result, validationErr = dv.ValidateDomainControlActual(domain, token)
		}

		if validationErr != nil {
			return fmt.Errorf("validation error for domain %s: %w", domain, validationErr)
		}

		if !result.Valid {
			return fmt.Errorf("domain validation failed for %s: %s", domain, result.Details)
		}
	}

	return nil
}

func (dv *DomainValidator) SetTimeouts(dnsTimeout, httpTimeout time.Duration) {
	dv.dnsTimeout = dnsTimeout
	dv.httpTimeout = httpTimeout
	dv.httpClient.Timeout = httpTimeout
}

func (dv *DomainValidator) VerifyCAA(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dv.dnsTimeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: 5 * time.Second,
			}
			return dialer.DialContext(ctx, network, "8.8.8.8:53")
		},
	}
	
	caaRecords, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil
	}

	hasCAA := false
	hasQuantumCAAuth := false
	
	for _, record := range caaRecords {
		if strings.Contains(record, "issue") || strings.Contains(record, "issuewild") {
			hasCAA = true
			if strings.Contains(record, "quantumca.com") {
				hasQuantumCAAuth = true
			}
		}
	}

	if hasCAA && !hasQuantumCAAuth {
		return fmt.Errorf("CAA records present but do not authorize QuantumCA")
	}

	return nil
}

func (dv *DomainValidator) CheckDomainReachability(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	
	ports := []string{"80", "443"}
	
	for _, port := range ports {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, port))
		if err != nil {
			continue
		}
		conn.Close()
		return nil
	}

	return fmt.Errorf("domain %s is not reachable on ports 80 or 443", domain)
}

func (dv *DomainValidator) ValidateDomainControl(domain, token string) (*ValidationResult, error) {
	return dv.ValidateDomainControlActual(domain, token)
}

func (dv *DomainValidator) ValidateWildcardDomain(domain, token string) (*ValidationResult, error) {
	return dv.ValidateWildcardDomainActual(domain, token)
}