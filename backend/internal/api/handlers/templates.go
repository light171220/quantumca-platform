package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type TemplateHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewTemplateHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *TemplateHandler {
	return &TemplateHandler{
		db:     db,
		config: config,
		logger: logger,
	}
}

func (h *TemplateHandler) List(c *gin.Context) {
	query := `SELECT id, name, description, key_usages, ext_key_usages, validity_days, 
			  max_validity_days, is_ca, path_length, policies, status, created_at, updated_at
			  FROM certificate_templates WHERE status = 'active' ORDER BY name`

	rows, err := h.db.Query(query)
	if err != nil {
		h.logger.LogError(err, "Failed to get certificate templates", nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get templates"})
		return
	}
	defer rows.Close()

	var templates []storage.CertificateTemplate
	for rows.Next() {
		var template storage.CertificateTemplate
		var keyUsagesJSON, extKeyUsagesJSON, policiesJSON sql.NullString
		var pathLength sql.NullInt64

		err := rows.Scan(&template.ID, &template.Name, &template.Description,
			&keyUsagesJSON, &extKeyUsagesJSON, &template.ValidityDays,
			&template.MaxValidityDays, &template.IsCA, &pathLength,
			&policiesJSON, &template.Status, &template.CreatedAt, &template.UpdatedAt)
		if err != nil {
			continue
		}

		if pathLength.Valid {
			pathLengthInt := int(pathLength.Int64)
			template.PathLength = &pathLengthInt
		}

		templates = append(templates, template)
	}

	c.JSON(http.StatusOK, templates)
}

func (h *TemplateHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	query := `SELECT id, name, description, key_usages, ext_key_usages, validity_days, 
			  max_validity_days, is_ca, path_length, policies, status, created_at, updated_at
			  FROM certificate_templates WHERE id = ? AND status = 'active'`

	var template storage.CertificateTemplate
	var keyUsagesJSON, extKeyUsagesJSON, policiesJSON sql.NullString
	var pathLength sql.NullInt64

	err = h.db.QueryRow(query, id).Scan(&template.ID, &template.Name, &template.Description,
		&keyUsagesJSON, &extKeyUsagesJSON, &template.ValidityDays,
		&template.MaxValidityDays, &template.IsCA, &pathLength,
		&policiesJSON, &template.Status, &template.CreatedAt, &template.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
			return
		}
		h.logger.LogError(err, "Failed to get certificate template", map[string]interface{}{
			"template_id": id,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get template"})
		return
	}

	if pathLength.Valid {
		pathLengthInt := int(pathLength.Int64)
		template.PathLength = &pathLengthInt
	}

	c.JSON(http.StatusOK, template)
}