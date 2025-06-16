package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

func GenerateRequestID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func HashPrefix(input string, length int) string {
	hash := sha256.Sum256([]byte(input))
	encoded := fmt.Sprintf("%x", hash)
	if len(encoded) > length {
		return encoded[:length]
	}
	return encoded
}

func SanitizeFilename(filename string) string {
	filename = strings.TrimSpace(filename)
	
	reg := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	filename = reg.ReplaceAllString(filename, "_")
	
	if len(filename) > 200 {
		filename = filename[:200]
	}
	
	return filename
}

func IsValidCertificateStatus(status string) bool {
	validStatuses := []string{"active", "revoked", "expired"}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}

func SafeFilePath(basePath, userPath string) (string, error) {
	cleanedPath := filepath.Clean(userPath)
	
	fullPath := filepath.Join(basePath, cleanedPath)
	
	if !strings.HasPrefix(fullPath, filepath.Clean(basePath)+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid file path")
	}
	
	return fullPath, nil
}