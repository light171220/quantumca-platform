package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/utils"
)

type HealthHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewHealthHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *HealthHandler {
	return &HealthHandler{
		db:     db,
		config: config,
		logger: logger,
	}
}

type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Checks    map[string]string `json:"checks"`
}

type LivenessResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

type ReadinessResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks"`
}

type MetricsResponse struct {
	DatabaseConnections int `json:"database_connections"`
	ActiveCertificates  int `json:"active_certificates"`
	TotalCustomers      int `json:"total_customers"`
	Timestamp           string `json:"timestamp"`
}

var startTime = time.Now()

func (h *HealthHandler) Check(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]string)
	overallStatus := "healthy"

	if err := h.db.PingContext(ctx); err != nil {
		checks["database"] = "unhealthy: " + err.Error()
		overallStatus = "unhealthy"
	} else {
		checks["database"] = "healthy"
	}

	var count int
	err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM customers LIMIT 1").Scan(&count)
	if err != nil {
		checks["database_query"] = "unhealthy: " + err.Error()
		overallStatus = "unhealthy"
	} else {
		checks["database_query"] = "healthy"
	}

	uptime := time.Since(startTime)

	response := &HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   "1.0.0",
		Uptime:    uptime.String(),
		Checks:    checks,
	}

	statusCode := http.StatusOK
	if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}

func (h *HealthHandler) Liveness(c *gin.Context) {
	response := &LivenessResponse{
		Status:    "alive",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *HealthHandler) Readiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string)
	overallStatus := "ready"

	if err := h.db.PingContext(ctx); err != nil {
		checks["database"] = "not_ready: " + err.Error()
		overallStatus = "not_ready"
	} else {
		checks["database"] = "ready"
	}

	var count int
	err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM customers LIMIT 1").Scan(&count)
	if err != nil {
		checks["database_query"] = "not_ready: " + err.Error()
		overallStatus = "not_ready"
	} else {
		checks["database_query"] = "ready"
	}

	response := &ReadinessResponse{
		Status:    overallStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
	}

	statusCode := http.StatusOK
	if overallStatus == "not_ready" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}

func (h *HealthHandler) Metrics(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	stats := h.db.Stats()
	
	var activeCerts int
	err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE status = 'active'").Scan(&activeCerts)
	if err != nil {
		h.logger.LogError(err, "Failed to get active certificates count", nil)
		activeCerts = -1
	}

	var totalCustomers int
	err = h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM customers WHERE status = 'active'").Scan(&totalCustomers)
	if err != nil {
		h.logger.LogError(err, "Failed to get total customers count", nil)
		totalCustomers = -1
	}

	response := &MetricsResponse{
		DatabaseConnections: stats.OpenConnections,
		ActiveCertificates:  activeCerts,
		TotalCustomers:      totalCustomers,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}
