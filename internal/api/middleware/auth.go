package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/storage"
)

func APIKeyAuth(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		apiKey := parts[1]
		customer, err := storage.GetCustomerByAPIKey(db, apiKey)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication error"})
			}
			c.Abort()
			return
		}

		if customer.Status != "active" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Account inactive"})
			c.Abort()
			return
		}

		c.Set("customer", customer)
		c.Next()
	}
}