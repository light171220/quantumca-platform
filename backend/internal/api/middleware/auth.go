package middleware

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"
)

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  *time.Ticker
}

type CustomerRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rates    map[int]rate.Limit
	bursts   map[int]int
	cleanup  *time.Ticker
}

type BruteForceProtection struct {
	attempts map[string]int
	mu       sync.RWMutex
	cleanup  *time.Ticker
}

var (
	globalRateLimiter    *RateLimiter
	customerRateLimiter  *CustomerRateLimiter
	bruteForceProtection *BruteForceProtection
)

func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Every(time.Minute / time.Duration(requestsPerMinute)),
		burst:    requestsPerMinute,
		cleanup:  time.NewTicker(time.Hour),
	}
	
	go rl.cleanupExpiredLimiters()
	return rl
}

func NewCustomerRateLimiter() *CustomerRateLimiter {
	crl := &CustomerRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rates:    make(map[int]rate.Limit),
		bursts:   make(map[int]int),
		cleanup:  time.NewTicker(time.Hour),
	}
	
	crl.rates[1] = rate.Every(time.Minute / 60)
	crl.rates[2] = rate.Every(time.Minute / 120)
	crl.rates[3] = rate.Every(time.Minute / 300)
	
	crl.bursts[1] = 60
	crl.bursts[2] = 120
	crl.bursts[3] = 300
	
	go crl.cleanupExpiredLimiters()
	return crl
}

func NewBruteForceProtection() *BruteForceProtection {
	bfp := &BruteForceProtection{
		attempts: make(map[string]int),
		cleanup:  time.NewTicker(15 * time.Minute),
	}
	
	go bfp.cleanupAttempts()
	return bfp
}

func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		if limiter, exists = rl.limiters[key]; !exists {
			limiter = rate.NewLimiter(rl.rate, rl.burst)
			rl.limiters[key] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter
}

func (rl *RateLimiter) cleanupExpiredLimiters() {
	for range rl.cleanup.C {
		rl.mu.Lock()
		for key, limiter := range rl.limiters {
			if limiter.TokensAt(time.Now()) == float64(rl.burst) {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Stop() {
	rl.cleanup.Stop()
}

func (crl *CustomerRateLimiter) getLimiter(key string, tier int) *rate.Limiter {
	crl.mu.RLock()
	limiter, exists := crl.limiters[key]
	crl.mu.RUnlock()

	if !exists {
		crl.mu.Lock()
		if limiter, exists = crl.limiters[key]; !exists {
			tierRate, rateExists := crl.rates[tier]
			tierBurst, burstExists := crl.bursts[tier]
			
			if !rateExists || !burstExists {
				tierRate = rate.Every(time.Minute / 60)
				tierBurst = 60
			}
			
			limiter = rate.NewLimiter(tierRate, tierBurst)
			crl.limiters[key] = limiter
		}
		crl.mu.Unlock()
	}

	return limiter
}

func (crl *CustomerRateLimiter) cleanupExpiredLimiters() {
	for range crl.cleanup.C {
		crl.mu.Lock()
		for key, limiter := range crl.limiters {
			if limiter.Tokens() >= float64(limiter.Burst()) {
				delete(crl.limiters, key)
			}
		}
		crl.mu.Unlock()
	}
}

func (crl *CustomerRateLimiter) Stop() {
	crl.cleanup.Stop()
}

func (bfp *BruteForceProtection) recordAttempt(ip string) int {
	bfp.mu.Lock()
	defer bfp.mu.Unlock()
	
	bfp.attempts[ip]++
	return bfp.attempts[ip]
}

func (bfp *BruteForceProtection) getAttempts(ip string) int {
	bfp.mu.RLock()
	defer bfp.mu.RUnlock()
	
	return bfp.attempts[ip]
}

func (bfp *BruteForceProtection) resetAttempts(ip string) {
	bfp.mu.Lock()
	defer bfp.mu.Unlock()
	
	delete(bfp.attempts, ip)
}

func (bfp *BruteForceProtection) cleanupAttempts() {
	for range bfp.cleanup.C {
		bfp.mu.Lock()
		bfp.attempts = make(map[string]int)
		bfp.mu.Unlock()
	}
}

func (bfp *BruteForceProtection) Stop() {
	bfp.cleanup.Stop()
}

func InitRateLimiter(requestsPerMinute int) {
	if globalRateLimiter != nil {
		globalRateLimiter.Stop()
	}
	globalRateLimiter = NewRateLimiter(requestsPerMinute)
	
	if customerRateLimiter != nil {
		customerRateLimiter.Stop()
	}
	customerRateLimiter = NewCustomerRateLimiter()
	
	if bruteForceProtection != nil {
		bruteForceProtection.Stop()
	}
	bruteForceProtection = NewBruteForceProtection()
}

func APIKeyAuth(db *sql.DB, logger *utils.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		if bruteForceProtection != nil {
			attempts := bruteForceProtection.getAttempts(clientIP)
			if attempts >= 10 {
				logger.LogSecurityEvent("brute_force_blocked", "", clientIP, map[string]interface{}{
					"attempts": attempts,
				})
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts"})
				c.Abort()
				return
			}
		}
		
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			bruteForceProtection.recordAttempt(clientIP)
			logger.LogSecurityEvent("missing_auth_header", "", clientIP, map[string]interface{}{
				"endpoint": c.FullPath(),
				"method":   c.Request.Method,
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			bruteForceProtection.recordAttempt(clientIP)
			logger.LogSecurityEvent("invalid_auth_format", "", clientIP, map[string]interface{}{
				"header_prefix": authHeader[:min(20, len(authHeader))],
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		apiKey := strings.TrimSpace(parts[1])
		if len(apiKey) < 32 || len(apiKey) > 128 {
			bruteForceProtection.recordAttempt(clientIP)
			logger.LogSecurityEvent("invalid_api_key_length", "", clientIP, map[string]interface{}{
				"length": len(apiKey),
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key format"})
			c.Abort()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		customer, err := storage.GetCustomerByAPIKeyWithContext(ctx, db, apiKey)
		if err != nil {
			bruteForceProtection.recordAttempt(clientIP)
			if err == sql.ErrNoRows {
				logger.LogSecurityEvent("invalid_api_key", "", clientIP, map[string]interface{}{
					"api_key_prefix": utils.HashPrefix(apiKey, 8),
				})
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			} else {
				logger.LogError(err, "Database error during authentication", map[string]interface{}{
					"ip": clientIP,
				})
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication service unavailable"})
			}
			c.Abort()
			return
		}

		if customer.Status != "active" {
			bruteForceProtection.recordAttempt(clientIP)
			logger.LogSecurityEvent("inactive_account_access", utils.HashPrefix(customer.APIKey, 8), clientIP, map[string]interface{}{
				"customer_id": customer.ID,
				"status":      customer.Status,
			})
			c.JSON(http.StatusForbidden, gin.H{"error": "Account is not active"})
			c.Abort()
			return
		}
		
		bruteForceProtection.resetAttempts(clientIP)

		c.Set("customer", customer)
		c.Set("customer_id", customer.ID)
		c.Set("user_id", utils.HashPrefix(customer.APIKey, 8))
		c.Set("tier", customer.Tier)
		c.Next()
	}
}

func JWTAuth(jwtSecret string, logger *utils.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if len(tokenString) == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Empty token"})
			c.Abort()
			return
		}

		claims, err := utils.ValidateJWT(tokenString, jwtSecret)
		if err != nil {
			logger.LogSecurityEvent("invalid_jwt", "", c.ClientIP(), map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		
		if time.Now().After(claims.ExpiresAt.Time) {
			logger.LogSecurityEvent("expired_jwt", "", c.ClientIP(), map[string]interface{}{
				"expired_at": claims.ExpiresAt.Time,
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("customer_id", claims.CustomerID)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func RateLimit(requestsPerMinute int) gin.HandlerFunc {
	if globalRateLimiter == nil {
		InitRateLimiter(requestsPerMinute)
	}

	return func(c *gin.Context) {
		key := c.ClientIP()
		
		var limiter *rate.Limiter
		
		if customerID, exists := c.Get("customer_id"); exists {
			if custID, ok := customerID.(int); ok {
				if tier, tierExists := c.Get("tier"); tierExists {
					if userTier, tierOk := tier.(int); tierOk {
						key = fmt.Sprintf("%s:%d", key, custID)
						limiter = customerRateLimiter.getLimiter(key, userTier)
					}
				}
			}
		}
		
		if limiter == nil {
			limiter = globalRateLimiter.getLimiter(key)
		}

		if !limiter.Allow() {
			c.Header("X-RateLimit-Limit", strconv.Itoa(requestsPerMinute))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": 60,
			})
			c.Abort()
			return
		}

		remaining := limiter.Tokens()
		c.Header("X-RateLimit-Limit", strconv.Itoa(requestsPerMinute))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(int(remaining)))
		c.Next()
	}
}

func RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "No role found"})
			c.Abort()
			return
		}

		userRole, ok := role.(string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid role format"})
			c.Abort()
			return
		}

		if subtle.ConstantTimeCompare([]byte(userRole), []byte(requiredRole)) != 1 {
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "Insufficient permissions",
				"required_role": requiredRole,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func RequireTier(minTier int) gin.HandlerFunc {
	return func(c *gin.Context) {
		tier, exists := c.Get("tier")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tier information required"})
			return
		}

		userTier, ok := tier.(int)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid tier format"})
			c.Abort()
			return
		}

		if userTier < minTier {
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "Insufficient service tier",
				"required_tier": minTier,
				"current_tier":  userTier,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-Permitted-Cross-Domain-Policies", "none")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Next()
	}
}

func AuditLog(logger *utils.Logger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		userID := ""
		customerID := 0
		
		if uid, exists := param.Keys["user_id"]; exists {
			if uidStr, ok := uid.(string); ok {
				userID = uidStr
			}
		}
		
		if cid, exists := param.Keys["customer_id"]; exists {
			if cidInt, ok := cid.(int); ok {
				customerID = cidInt
			}
		}

		logger.LogAPIAccess(
			param.Method,
			param.Path,
			param.ClientIP,
			param.StatusCode,
			param.Latency,
			userID,
		)

		if param.StatusCode >= 400 {
			logger.LogSecurityEvent("api_error", userID, param.ClientIP, map[string]interface{}{
				"method":      param.Method,
				"path":        param.Path,
				"status_code": param.StatusCode,
				"customer_id": customerID,
				"error":       param.ErrorMessage,
				"latency_ms":  param.Latency.Milliseconds(),
			})
		}

		return ""
	})
}

func RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request body too large",
				"max_size": maxSize,
			})
			c.Abort()
			return
		}
		
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}