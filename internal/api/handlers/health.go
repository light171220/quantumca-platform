package handlers

import (
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
	Checks    map[string]string `json:"checks"`
}

func (h *HealthHandler) Check(c *gin.Context) {
	checks := make(map[string]string)
	overallStatus := "healthy"

	if err := h.db.Ping(); err != nil {
		checks["database"] = "unhealthy: " + err.Error()
		overallStatus = "unhealthy"
	} else {
		checks["database"] = "healthy"
	}

	response := &HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   "1.0.0",
		Checks:    checks,
	}

	statusCode := http.StatusOK
	if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}