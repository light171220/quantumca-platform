package utils

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	emailRegex  = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

func ValidateDomainName(domain string) error {
	if len(domain) == 0 {
		return fmt.Errorf("domain name cannot be empty")
	}
	
	if len(domain) > 253 {
		return fmt.Errorf("domain name too long")
	}
	
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("domain name cannot start or end with a dot")
	}
	
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain name format")
	}
	
	return nil
}

func ValidateEmail(email string) error {
	if len(email) == 0 {
		return fmt.Errorf("email cannot be empty")
	}
	
	if len(email) > 254 {
		return fmt.Errorf("email too long")
	}
	
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	
	return nil
}

func ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format")
	}
	return nil
}

func ValidateCommonName(cn string) error {
	if len(cn) == 0 {
		return fmt.Errorf("common name cannot be empty")
	}
	
	if len(cn) > 64 {
		return fmt.Errorf("common name too long")
	}
	
	if strings.Contains(cn, "\x00") {
		return fmt.Errorf("common name contains null character")
	}
	
	return nil
}

func ValidateSubjectAltNames(sans []string) error {
	if len(sans) > 100 {
		return fmt.Errorf("too many subject alternative names")
	}
	
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if len(san) == 0 {
			continue
		}
		
		if net.ParseIP(san) == nil && ValidateDomainName(san) != nil {
			return fmt.Errorf("invalid subject alternative name: %s", san)
		}
	}
	
	return nil
}

func ValidateValidityDays(days int) error {
	if days <= 0 {
		return fmt.Errorf("validity days must be positive")
	}
	
	if days > 3650 {
		return fmt.Errorf("validity days cannot exceed 10 years")
	}
	
	return nil
}

func ValidateCustomerTier(tier int) error {
	if tier < 1 || tier > 3 {
		return fmt.Errorf("invalid customer tier, must be 1, 2, or 3")
	}
	
	return nil
}

func SanitizeString(input string) string {
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "\x00", "")
	input = strings.ReplaceAll(input, "\r", "")
	input = strings.ReplaceAll(input, "\n", "")
	input = strings.ReplaceAll(input, "\t", " ")
	
	return input
}

func ValidateCertificateLifetime(notBefore, notAfter time.Time) error {
	now := time.Now()
	
	if notBefore.After(notAfter) {
		return fmt.Errorf("certificate not_before cannot be after not_after")
	}
	
	if notAfter.Before(now) {
		return fmt.Errorf("certificate not_after cannot be in the past")
	}
	
	if notBefore.Before(now.Add(-24*time.Hour)) {
		return fmt.Errorf("certificate not_before cannot be more than 24 hours in the past")
	}
	
	maxLifetime := 10 * 365 * 24 * time.Hour
	if notAfter.Sub(notBefore) > maxLifetime {
		return fmt.Errorf("certificate lifetime cannot exceed 10 years")
	}
	
	return nil
}