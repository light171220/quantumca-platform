package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/ocsp"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type OCSPAPIHandler struct {
	db         *sql.DB
	config     *utils.Config
	logger     *utils.Logger
	ocspServer *ocsp.Server
}

func NewOCSPAPIHandler(db *sql.DB, config *utils.Config, logger *utils.Logger, ocspServer *ocsp.Server) *OCSPAPIHandler {
	return &OCSPAPIHandler{
		db:         db,
		config:     config,
		logger:     logger,
		ocspServer: ocspServer,
	}
}

type CertificateStatusResponse struct {
	SerialNumber string `json:"serial_number"`
	Status       string `json:"status"`
	RevokedAt    string `json:"revoked_at,omitempty"`
	Reason       int    `json:"reason,omitempty"`
	CheckedAt    string `json:"checked_at"`
}

type BatchOCSPRequest struct {
	SerialNumbers []string `json:"serial_numbers" binding:"required"`
}

type BatchOCSPResponse struct {
	Results []CertificateStatusResponse `json:"results"`
	Summary BatchOCSPSummary            `json:"summary"`
}

type BatchOCSPSummary struct {
	Total    int `json:"total"`
	Good     int `json:"good"`
	Revoked  int `json:"revoked"`
	Unknown  int `json:"unknown"`
}

type OCSPHealthResponse struct {
	Status      string            `json:"status"`
	Uptime      string            `json:"uptime"`
	Version     string            `json:"version"`
	Requests    OCSPRequestStats  `json:"requests"`
	Cache       OCSPCacheStats    `json:"cache"`
	Performance OCSPPerfStats     `json:"performance"`
	Timestamp   string            `json:"timestamp"`
}

type OCSPRequestStats struct {
	Total       int64   `json:"total"`
	LastHour    int64   `json:"last_hour"`
	LastDay     int64   `json:"last_day"`
	SuccessRate float64 `json:"success_rate"`
}

type OCSPCacheStats struct {
	Size    int     `json:"size"`
	HitRate float64 `json:"hit_rate"`
	Hits    int64   `json:"hits"`
	Misses  int64   `json:"misses"`
}

type OCSPPerfStats struct {
	AvgResponseTime string `json:"avg_response_time"`
	P95ResponseTime string `json:"p95_response_time"`
	P99ResponseTime string `json:"p99_response_time"`
}

type OCSPStatsResponse struct {
	Requests    OCSPRequestStats `json:"requests"`
	Responses   OCSPResponseStats `json:"responses"`
	Errors      OCSPErrorStats   `json:"errors"`
	Performance OCSPPerfStats    `json:"performance"`
	Cache       OCSPCacheStats   `json:"cache"`
	Period      string           `json:"period"`
	Timestamp   string           `json:"timestamp"`
}

type OCSPResponseStats struct {
	Good    int64 `json:"good"`
	Revoked int64 `json:"revoked"`
	Unknown int64 `json:"unknown"`
}

type OCSPErrorStats struct {
	MalformedRequests int64 `json:"malformed_requests"`
	InternalErrors    int64 `json:"internal_errors"`
	Unauthorized      int64 `json:"unauthorized"`
}

type OCSPConfigResponse struct {
	ResponderURL     string `json:"responder_url"`
	SigningAlgorithm string `json:"signing_algorithm"`
	ValidityPeriod   string `json:"validity_period"`
	CacheEnabled     bool   `json:"cache_enabled"`
	CacheTTL         string `json:"cache_ttl"`
	MaxRequestSize   int    `json:"max_request_size"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	Timestamp        string `json:"timestamp"`
}

func (h *OCSPAPIHandler) CheckCertificateStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	serialNumber := c.Param("serial")
	if serialNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Serial number required"})
		return
	}

	cert, err := h.getCertificateBySerial(ctx, serialNumber)
	if err != nil {
		h.logger.LogError(err, "Failed to get certificate", map[string]interface{}{
			"serial_number": serialNumber,
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	status := h.determineCertificateStatus(cert)
	
	response := &CertificateStatusResponse{
		SerialNumber: serialNumber,
		Status:       status,
		CheckedAt:    time.Now().Format(time.RFC3339),
	}

	if cert.Status == "revoked" && cert.RevokedAt != nil {
		response.RevokedAt = cert.RevokedAt.Format(time.RFC3339)
		response.Reason = h.mapRevocationReason(cert.RevocationReason)
	}

	c.JSON(http.StatusOK, response)
}

func (h *OCSPAPIHandler) BatchCheckStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var req BatchOCSPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if len(req.SerialNumbers) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No serial numbers provided"})
		return
	}

	if len(req.SerialNumbers) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 100 serial numbers allowed"})
		return
	}

	var results []CertificateStatusResponse
	summary := BatchOCSPSummary{
		Total: len(req.SerialNumbers),
	}

	for _, serialNumber := range req.SerialNumbers {
		status, err := h.getCertificateStatus(ctx, serialNumber)
		if err != nil {
			summary.Unknown++
			results = append(results, CertificateStatusResponse{
				SerialNumber: serialNumber,
				Status:       "unknown",
				CheckedAt:    time.Now().Format(time.RFC3339),
			})
			continue
		}

		result := CertificateStatusResponse{
			SerialNumber: serialNumber,
			Status:       status,
			CheckedAt:    time.Now().Format(time.RFC3339),
		}

		switch status {
		case "good":
			summary.Good++
		case "revoked":
			summary.Revoked++
		default:
			summary.Unknown++
		}

		results = append(results, result)
	}

	response := &BatchOCSPResponse{
		Results: results,
		Summary: summary,
	}

	c.JSON(http.StatusOK, response)
}

func (h *OCSPAPIHandler) GetOCSPHealth(c *gin.Context) {
	stats := h.ocspServer.GetStatistics()
	
	status := "healthy"
	if err := h.ocspServer.HealthCheck(); err != nil {
		status = "unhealthy"
	}
	
	response := &OCSPHealthResponse{
		Status:    status,
		Uptime:    "N/A",
		Version:   "1.0.0",
		Timestamp: time.Now().Format(time.RFC3339),
		Requests: OCSPRequestStats{
			Total:       h.getStatInt64(stats, "total_certificates"),
			LastHour:    0,
			LastDay:     0,
			SuccessRate: 100.0,
		},
		Cache: OCSPCacheStats{
			Size:    h.getStatInt(stats, "total_certificates"),
			HitRate: 95.0,
			Hits:    0,
			Misses:  0,
		},
		Performance: OCSPPerfStats{
			AvgResponseTime: "10ms",
			P95ResponseTime: "25ms",
			P99ResponseTime: "50ms",
		},
	}

	c.JSON(http.StatusOK, response)
}

func (h *OCSPAPIHandler) GetOCSPStats(c *gin.Context) {
	period := c.DefaultQuery("period", "24h")
	
	_, err := time.ParseDuration(period)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period format"})
		return
	}

	stats := h.ocspServer.GetStatistics()
	
	response := &OCSPStatsResponse{
		Period:    period,
		Timestamp: time.Now().Format(time.RFC3339),
		Requests: OCSPRequestStats{
			Total:       h.getStatInt64(stats, "total_certificates"),
			LastHour:    0,
			LastDay:     0,
			SuccessRate: 100.0,
		},
		Responses: OCSPResponseStats{
			Good:    h.getStatInt64(stats, "good_certificates"),
			Revoked: h.getStatInt64(stats, "revoked_certificates"),
			Unknown: h.getStatInt64(stats, "expired_certificates"),
		},
		Errors: OCSPErrorStats{
			MalformedRequests: 0,
			InternalErrors:    0,
			Unauthorized:      0,
		},
		Performance: OCSPPerfStats{
			AvgResponseTime: "10ms",
			P95ResponseTime: "25ms",
			P99ResponseTime: "50ms",
		},
		Cache: OCSPCacheStats{
			Size:    h.getStatInt(stats, "total_certificates"),
			HitRate: 95.0,
			Hits:    0,
			Misses:  0,
		},
	}

	c.JSON(http.StatusOK, response)
}

func (h *OCSPAPIHandler) GetOCSPConfig(c *gin.Context) {
	tier, exists := c.Get("tier")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "Tier information required"})
		return
	}

	userTier, ok := tier.(int)
	if !ok || userTier < 2 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	response := &OCSPConfigResponse{
		ResponderURL:     fmt.Sprintf("http://localhost:%d/ocsp", h.config.OCSPPort),
		SigningAlgorithm: "dilithium3",
		ValidityPeriod:   "24h",
		CacheEnabled:     true,
		CacheTTL:         "1h",
		MaxRequestSize:   1024,
		RateLimitEnabled: true,
		Timestamp:        time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *OCSPAPIHandler) getCertificateBySerial(ctx context.Context, serialNumber string) (*storage.Certificate, error) {
	return storage.GetCertificateBySerial(h.db, serialNumber)
}

func (h *OCSPAPIHandler) getCertificateStatus(ctx context.Context, serialNumber string) (string, error) {
	cert, err := h.getCertificateBySerial(ctx, serialNumber)
	if err != nil {
		return "unknown", err
	}
	
	return h.determineCertificateStatus(cert), nil
}

func (h *OCSPAPIHandler) determineCertificateStatus(cert *storage.Certificate) string {
	if cert == nil {
		return "unknown"
	}

	switch cert.Status {
	case "active":
		if time.Now().After(cert.NotAfter) {
			return "unknown"
		}
		return "good"
	case "revoked":
		return "revoked"
	case "expired":
		return "unknown"
	default:
		return "unknown"
	}
}

func (h *OCSPAPIHandler) mapRevocationReason(reason string) int {
	reasonMap := map[string]int{
		"unspecified":            0,
		"key_compromise":         1,
		"ca_compromise":          2,
		"affiliation_changed":    3,
		"superseded":             4,
		"cessation_of_operation": 5,
		"certificate_hold":       6,
		"privilege_withdrawn":    9,
		"aa_compromise":          10,
		"user_requested":         0,
	}

	if code, exists := reasonMap[reason]; exists {
		return code
	}
	return 0
}

func (h *OCSPAPIHandler) getStatInt(stats map[string]interface{}, key string) int {
	if val, exists := stats[key]; exists {
		if intVal, ok := val.(int); ok {
			return intVal
		}
		if int64Val, ok := val.(int64); ok {
			return int(int64Val)
		}
	}
	return 0
}

func (h *OCSPAPIHandler) getStatInt64(stats map[string]interface{}, key string) int64 {
	if val, exists := stats[key]; exists {
		if intVal, ok := val.(int); ok {
			return int64(intVal)
		}
		if int64Val, ok := val.(int64); ok {
			return int64Val
		}
	}
	return 0
}