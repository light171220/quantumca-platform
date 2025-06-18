package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type AuditHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewAuditHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *AuditHandler {
	return &AuditHandler{
		db:     db,
		config: config,
		logger: logger,
	}
}

type AuditLogResponse struct {
	ID         int                    `json:"id"`
	UserID     string                 `json:"user_id"`
	CustomerID int                    `json:"customer_id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Details    map[string]interface{} `json:"details"`
	CreatedAt  string                 `json:"created_at"`
}

type AuditListResponse struct {
	Logs       []AuditLogResponse `json:"logs"`
	Total      int                `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

func (h *AuditHandler) List(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	page := 1
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 && p <= 1000 {
			page = p
		}
	}

	pageSize := 50
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	action := utils.SanitizeString(c.Query("action"))
	resource := utils.SanitizeString(c.Query("resource"))
	userID := utils.SanitizeString(c.Query("user_id"))
	
	var fromDate, toDate time.Time
	if fromStr := c.Query("from"); fromStr != "" {
		if parsed, err := time.Parse(time.RFC3339, fromStr); err == nil {
			fromDate = parsed
		}
	}
	if toStr := c.Query("to"); toStr != "" {
		if parsed, err := time.Parse(time.RFC3339, toStr); err == nil {
			toDate = parsed
		}
	}

	logs, total, err := h.getAuditLogs(ctx, custID, page, pageSize, action, resource, userID, fromDate, toDate)
	if err != nil {
		h.logger.LogError(err, "Failed to get audit logs", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get audit logs"})
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	response := &AuditListResponse{
		Logs:       logs,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func (h *AuditHandler) Get(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid audit log ID"})
		return
	}

	customerID, exists := c.Get("customer_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication required"})
		return
	}

	custID, ok := customerID.(int)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	log, err := h.getAuditLog(ctx, id, custID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Audit log not found"})
			return
		}
		h.logger.LogError(err, "Failed to get audit log", map[string]interface{}{
			"audit_log_id": id,
			"customer_id":  custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get audit log"})
		return
	}

	c.JSON(http.StatusOK, log)
}

func (h *AuditHandler) getAuditLogs(ctx context.Context, customerID, page, pageSize int, action, resource, userID string, fromDate, toDate time.Time) ([]AuditLogResponse, int, error) {
	offset := (page - 1) * pageSize
	
	whereClause := "WHERE customer_id = ?"
	args := []interface{}{customerID}
	
	if action != "" {
		whereClause += " AND action = ?"
		args = append(args, action)
	}
	
	if resource != "" {
		whereClause += " AND resource = ?"
		args = append(args, resource)
	}
	
	if userID != "" {
		whereClause += " AND user_id = ?"
		args = append(args, userID)
	}
	
	if !fromDate.IsZero() {
		whereClause += " AND created_at >= ?"
		args = append(args, fromDate)
	}
	
	if !toDate.IsZero() {
		whereClause += " AND created_at <= ?"
		args = append(args, toDate)
	}

	countQuery := "SELECT COUNT(*) FROM audit_logs " + whereClause
	var total int
	err := h.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `SELECT id, user_id, customer_id, action, resource, resource_id, 
			  ip_address, user_agent, details, created_at 
			  FROM audit_logs ` + whereClause + `
			  ORDER BY created_at DESC 
			  LIMIT ? OFFSET ?`
	
	args = append(args, pageSize, offset)
	
	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []AuditLogResponse
	for rows.Next() {
		var log AuditLogResponse
		var detailsJSON string
		var resourceID sql.NullString
		var ipAddress sql.NullString
		var userAgent sql.NullString
		var createdAt time.Time

		err := rows.Scan(&log.ID, &log.UserID, &log.CustomerID, &log.Action,
			&log.Resource, &resourceID, &ipAddress, &userAgent,
			&detailsJSON, &createdAt)
		if err != nil {
			continue
		}

		if resourceID.Valid {
			log.ResourceID = resourceID.String
		}
		if ipAddress.Valid {
			log.IPAddress = ipAddress.String
		}
		if userAgent.Valid {
			log.UserAgent = userAgent.String
		}

		log.CreatedAt = createdAt.Format(time.RFC3339)

		if detailsJSON != "" {
			if err := storage.UnmarshalJSON([]byte(detailsJSON), &log.Details); err != nil {
				log.Details = make(map[string]interface{})
			}
		} else {
			log.Details = make(map[string]interface{})
		}

		logs = append(logs, log)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (h *AuditHandler) getAuditLog(ctx context.Context, id, customerID int) (*AuditLogResponse, error) {
	query := `SELECT id, user_id, customer_id, action, resource, resource_id, 
			  ip_address, user_agent, details, created_at 
			  FROM audit_logs WHERE id = ? AND customer_id = ?`

	var log AuditLogResponse
	var detailsJSON string
	var resourceID sql.NullString
	var ipAddress sql.NullString
	var userAgent sql.NullString
	var createdAt time.Time

	err := h.db.QueryRowContext(ctx, query, id, customerID).Scan(&log.ID, &log.UserID, 
		&log.CustomerID, &log.Action, &log.Resource, &resourceID, 
		&ipAddress, &userAgent, &detailsJSON, &createdAt)
	if err != nil {
		return nil, err
	}

	if resourceID.Valid {
		log.ResourceID = resourceID.String
	}
	if ipAddress.Valid {
		log.IPAddress = ipAddress.String
	}
	if userAgent.Valid {
		log.UserAgent = userAgent.String
	}

	log.CreatedAt = createdAt.Format(time.RFC3339)

	if detailsJSON != "" {
		if err := storage.UnmarshalJSON([]byte(detailsJSON), &log.Details); err != nil {
			log.Details = make(map[string]interface{})
		}
	} else {
		log.Details = make(map[string]interface{})
	}

	return &log, nil
}