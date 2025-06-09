package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type CustomerHandler struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
}

func NewCustomerHandler(db *sql.DB, config *utils.Config, logger *utils.Logger) *CustomerHandler {
	return &CustomerHandler{
		db:     db,
		config: config,
		logger: logger,
	}
}

type CreateCustomerRequest struct {
	CompanyName string `json:"company_name" binding:"required"`
	Email       string `json:"email" binding:"required,email"`
	Tier        int    `json:"tier" binding:"required,min=1,max=3"`
}

type CustomerResponse struct {
	ID          int    `json:"id"`
	CompanyName string `json:"company_name"`
	Email       string `json:"email"`
	APIKey      string `json:"api_key"`
	Tier        int    `json:"tier"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

func (h *CustomerHandler) Create(c *gin.Context) {
	var req CreateCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	apiKey := uuid.New().String()

	customer := &storage.Customer{
		CompanyName: req.CompanyName,
		Email:       req.Email,
		APIKey:      apiKey,
		Tier:        req.Tier,
		Status:      "active",
	}

	id, err := storage.CreateCustomer(h.db, customer)
	if err != nil {
		h.logger.Error("Failed to create customer:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create customer"})
		return
	}

	response := &CustomerResponse{
		ID:          id,
		CompanyName: customer.CompanyName,
		Email:       customer.Email,
		APIKey:      customer.APIKey,
		Tier:        customer.Tier,
		Status:      customer.Status,
		CreatedAt:   customer.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *CustomerHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid customer ID"})
		return
	}

	customer, err := storage.GetCustomer(h.db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
			return
		}
		h.logger.Error("Failed to get customer:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get customer"})
		return
	}

	response := &CustomerResponse{
		ID:          customer.ID,
		CompanyName: customer.CompanyName,
		Email:       customer.Email,
		APIKey:      customer.APIKey,
		Tier:        customer.Tier,
		Status:      customer.Status,
		CreatedAt:   customer.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	c.JSON(http.StatusOK, response)
}