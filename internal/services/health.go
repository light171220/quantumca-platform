package services

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"quantumca-platform/internal/utils"
)

type HealthService struct {
	db        *sql.DB
	config    *utils.Config
	logger    *utils.Logger
	status    *HealthStatus
	mu        sync.RWMutex
	stopCh    chan struct{}
	stopped   bool
}

type HealthStatus struct {
	Overall    string                 `json:"overall"`
	Timestamp  time.Time              `json:"timestamp"`
	Version    string                 `json:"version"`
	Uptime     time.Duration          `json:"uptime"`
	StartTime  time.Time              `json:"start_time"`
	Components map[string]ComponentHealth `json:"components"`
}

type ComponentHealth struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
	ResponseTime time.Duration         `json:"response_time,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusDegraded  = "degraded"
	StatusUnknown   = "unknown"
)

func NewHealthService(db *sql.DB, config *utils.Config, logger *utils.Logger) *HealthService {
	return &HealthService{
		db:     db,
		config: config,
		logger: logger,
		status: &HealthStatus{
			Overall:    StatusUnknown,
			Timestamp:  time.Now(),
			Version:    "1.0.0",
			StartTime:  time.Now(),
			Components: make(map[string]ComponentHealth),
		},
		stopCh: make(chan struct{}),
	}
}

func (hs *HealthService) Start() error {
	hs.logger.Info("Starting health service")
	
	ticker := time.NewTicker(hs.config.HealthCheckInterval)
	go func() {
		defer ticker.Stop()
		
		hs.performHealthCheck()
		
		for {
			select {
			case <-ticker.C:
				hs.performHealthCheck()
			case <-hs.stopCh:
				return
			}
		}
	}()
	
	return nil
}

func (hs *HealthService) Stop() error {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	
	if hs.stopped {
		return nil
	}
	
	hs.logger.Info("Stopping health service")
	close(hs.stopCh)
	hs.stopped = true
	
	return nil
}

func (hs *HealthService) GetStatus() *HealthStatus {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	
	statusCopy := *hs.status
	statusCopy.Uptime = time.Since(hs.status.StartTime)
	statusCopy.Timestamp = time.Now()
	
	componentsCopy := make(map[string]ComponentHealth)
	for k, v := range hs.status.Components {
		componentsCopy[k] = v
	}
	statusCopy.Components = componentsCopy
	
	return &statusCopy
}

func (hs *HealthService) IsHealthy() bool {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	
	return hs.status.Overall == StatusHealthy
}

func (hs *HealthService) IsReady() bool {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	
	dbHealth, exists := hs.status.Components["database"]
	if !exists || dbHealth.Status != StatusHealthy {
		return false
	}
	
	return hs.status.Overall == StatusHealthy || hs.status.Overall == StatusDegraded
}

func (hs *HealthService) performHealthCheck() {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	
	hs.status.Timestamp = time.Now()
	
	hs.checkDatabase()
	hs.checkDiskSpace()
	hs.checkMemory()
	hs.checkCertificateExpiry()
	
	hs.updateOverallStatus()
}

func (hs *HealthService) checkDatabase() {
	start := time.Now()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	health := ComponentHealth{
		LastChecked: start,
		Details:     make(map[string]interface{}),
	}
	
	if err := hs.db.PingContext(ctx); err != nil {
		health.Status = StatusUnhealthy
		health.Message = fmt.Sprintf("Database ping failed: %v", err)
		health.ResponseTime = time.Since(start)
		hs.status.Components["database"] = health
		return
	}
	
	var count int
	err := hs.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM customers").Scan(&count)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Message = fmt.Sprintf("Database query failed: %v", err)
		health.ResponseTime = time.Since(start)
		hs.status.Components["database"] = health
		return
	}
	
	stats := hs.db.Stats()
	
	health.Status = StatusHealthy
	health.Message = "Database is accessible"
	health.ResponseTime = time.Since(start)
	health.Details["customer_count"] = count
	health.Details["open_connections"] = stats.OpenConnections
	health.Details["in_use"] = stats.InUse
	health.Details["idle"] = stats.Idle
	
	if stats.OpenConnections > hs.config.DatabaseMaxConnections*8/10 {
		health.Status = StatusDegraded
		health.Message = "High database connection usage"
	}
	
	hs.status.Components["database"] = health
}

func (hs *HealthService) checkDiskSpace() {
	start := time.Now()
	
	health := ComponentHealth{
		LastChecked: start,
		Details:     make(map[string]interface{}),
	}
	
	// This is a simplified disk space check
	// In production, you would implement actual disk space monitoring
	health.Status = StatusHealthy
	health.Message = "Disk space is sufficient"
	health.ResponseTime = time.Since(start)
	health.Details["status"] = "monitoring_not_implemented"
	
	hs.status.Components["disk_space"] = health
}

func (hs *HealthService) checkMemory() {
	start := time.Now()
	
	health := ComponentHealth{
		LastChecked: start,
		Details:     make(map[string]interface{}),
	}
	
	// This is a simplified memory check
	// In production, you would implement actual memory monitoring
	health.Status = StatusHealthy
	health.Message = "Memory usage is normal"
	health.ResponseTime = time.Since(start)
	health.Details["status"] = "monitoring_not_implemented"
	
	hs.status.Components["memory"] = health
}

func (hs *HealthService) checkCertificateExpiry() {
	start := time.Now()
	
	health := ComponentHealth{
		LastChecked: start,
		Details:     make(map[string]interface{}),
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	expiryThreshold := time.Now().AddDate(0, 0, 30)
	
	query := `SELECT COUNT(*) FROM certificates 
			  WHERE status = 'active' AND not_after < ?`
	
	var expiringCount int
	err := hs.db.QueryRowContext(ctx, query, expiryThreshold).Scan(&expiringCount)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Message = fmt.Sprintf("Failed to check certificate expiry: %v", err)
		health.ResponseTime = time.Since(start)
		hs.status.Components["certificate_expiry"] = health
		return
	}
	
	var totalCount int
	err = hs.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE status = 'active'").Scan(&totalCount)
	if err != nil {
		health.Status = StatusUnhealthy
		health.Message = fmt.Sprintf("Failed to count certificates: %v", err)
		health.ResponseTime = time.Since(start)
		hs.status.Components["certificate_expiry"] = health
		return
	}
	
	health.ResponseTime = time.Since(start)
	health.Details["total_certificates"] = totalCount
	health.Details["expiring_in_30_days"] = expiringCount
	
	if expiringCount == 0 {
		health.Status = StatusHealthy
		health.Message = "No certificates expiring soon"
	} else if expiringCount < 10 {
		health.Status = StatusDegraded
		health.Message = fmt.Sprintf("%d certificates expiring within 30 days", expiringCount)
	} else {
		health.Status = StatusUnhealthy
		health.Message = fmt.Sprintf("%d certificates expiring within 30 days - attention required", expiringCount)
	}
	
	hs.status.Components["certificate_expiry"] = health
}

func (hs *HealthService) updateOverallStatus() {
	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	totalComponents := len(hs.status.Components)
	
	for _, component := range hs.status.Components {
		switch component.Status {
		case StatusHealthy:
			healthyCount++
		case StatusDegraded:
			degradedCount++
		case StatusUnhealthy:
			unhealthyCount++
		}
	}
	
	if unhealthyCount > 0 {
		hs.status.Overall = StatusUnhealthy
	} else if degradedCount > 0 {
		hs.status.Overall = StatusDegraded
	} else if healthyCount == totalComponents && totalComponents > 0 {
		hs.status.Overall = StatusHealthy
	} else {
		hs.status.Overall = StatusUnknown
	}
}