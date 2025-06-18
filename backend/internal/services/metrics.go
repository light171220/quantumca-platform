package services

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"quantumca-platform/internal/utils"
)

type MetricsService struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
	server *http.Server
	
	certificatesTotal       *prometheus.CounterVec
	certificatesActive      prometheus.Gauge
	certificatesExpired     prometheus.Gauge
	certificatesRevoked     prometheus.Gauge
	customersTotal          prometheus.Gauge
	intermediateCAsTotal    *prometheus.CounterVec
	intermediateCAsActive   prometheus.Gauge
	ocspRequests            *prometheus.CounterVec
	apiRequests             *prometheus.CounterVec
	dbConnections           prometheus.Gauge
	backupStatus            prometheus.Gauge
	lastBackupTime          prometheus.Gauge
}

func NewMetricsService(db *sql.DB, config *utils.Config, logger *utils.Logger) *MetricsService {
	ms := &MetricsService{
		db:     db,
		config: config,
		logger: logger,
	}

	ms.initMetrics()
	return ms
}

func (ms *MetricsService) initMetrics() {
	ms.certificatesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quantumca_certificates_total",
			Help: "Total number of certificates issued",
		},
		[]string{"customer_tier", "status"},
	)

	ms.certificatesActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_certificates_active",
			Help: "Number of active certificates",
		},
	)

	ms.certificatesExpired = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_certificates_expired",
			Help: "Number of expired certificates",
		},
	)

	ms.certificatesRevoked = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_certificates_revoked",
			Help: "Number of revoked certificates",
		},
	)

	ms.customersTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_customers_total",
			Help: "Total number of customers",
		},
	)

	ms.intermediateCAsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quantumca_intermediate_cas_total",
			Help: "Total number of intermediate CAs created",
		},
		[]string{"customer_tier", "status"},
	)

	ms.intermediateCAsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_intermediate_cas_active",
			Help: "Number of active intermediate CAs",
		},
	)

	ms.ocspRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quantumca_ocsp_requests_total",
			Help: "Total number of OCSP requests",
		},
		[]string{"status"},
	)

	ms.apiRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quantumca_api_requests_total",
			Help: "Total number of API requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	ms.dbConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_db_connections_active",
			Help: "Number of active database connections",
		},
	)

	ms.backupStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_backup_status",
			Help: "Backup status (1 = success, 0 = failure)",
		},
	)

	ms.lastBackupTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "quantumca_last_backup_timestamp",
			Help: "Timestamp of last successful backup",
		},
	)

	prometheus.MustRegister(
		ms.certificatesTotal,
		ms.certificatesActive,
		ms.certificatesExpired,
		ms.certificatesRevoked,
		ms.customersTotal,
		ms.intermediateCAsTotal,
		ms.intermediateCAsActive,
		ms.ocspRequests,
		ms.apiRequests,
		ms.dbConnections,
		ms.backupStatus,
		ms.lastBackupTime,
	)
}

func (ms *MetricsService) Start() error {
	if !ms.config.MetricsEnabled {
		ms.logger.Info("Metrics service disabled")
		return nil
	}

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		ms.logger.Info("Metrics collection started")
		for range ticker.C {
			ms.collectMetrics()
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	
	ms.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", ms.config.MetricsPort),
		Handler: mux,
	}
	
	go func() {
		ms.logger.Infof("Metrics server listening on :%d", ms.config.MetricsPort)
		if err := ms.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ms.logger.LogError(err, "Metrics server failed", nil)
		}
	}()
	
	return nil
}

func (ms *MetricsService) Stop() error {
	if ms.server != nil {
		return ms.server.Close()
	}
	return nil
}

func (ms *MetricsService) collectMetrics() {
	ms.collectCertificateMetrics()
	ms.collectCustomerMetrics()
	ms.collectIntermediateCAMetrics()
	ms.collectDatabaseMetrics()
}

func (ms *MetricsService) collectCertificateMetrics() {
	query := `SELECT status, COUNT(*) FROM certificates GROUP BY status`
	rows, err := ms.db.Query(query)
	if err != nil {
		ms.logger.LogError(err, "Failed to collect certificate metrics", nil)
		return
	}
	defer rows.Close()

	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		statusCounts[status] = count
	}

	ms.certificatesActive.Set(float64(statusCounts["active"]))
	ms.certificatesExpired.Set(float64(statusCounts["expired"]))
	ms.certificatesRevoked.Set(float64(statusCounts["revoked"]))
}

func (ms *MetricsService) collectCustomerMetrics() {
	query := `SELECT COUNT(*) FROM customers WHERE status = 'active'`
	var count int
	if err := ms.db.QueryRow(query).Scan(&count); err != nil {
		ms.logger.LogError(err, "Failed to collect customer metrics", nil)
		return
	}

	ms.customersTotal.Set(float64(count))
}

func (ms *MetricsService) collectIntermediateCAMetrics() {
	query := `SELECT status, COUNT(*) FROM intermediate_cas GROUP BY status`
	rows, err := ms.db.Query(query)
	if err != nil {
		ms.logger.LogError(err, "Failed to collect intermediate CA metrics", nil)
		return
	}
	defer rows.Close()

	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		statusCounts[status] = count
	}

	ms.intermediateCAsActive.Set(float64(statusCounts["active"]))
}

func (ms *MetricsService) collectDatabaseMetrics() {
	stats := ms.db.Stats()
	ms.dbConnections.Set(float64(stats.OpenConnections))
}

func (ms *MetricsService) RecordCertificateIssued(customerTier int) {
	ms.certificatesTotal.WithLabelValues(
		fmt.Sprintf("tier_%d", customerTier),
		"issued",
	).Inc()
}

func (ms *MetricsService) RecordCertificateRevoked(customerTier int) {
	ms.certificatesTotal.WithLabelValues(
		fmt.Sprintf("tier_%d", customerTier),
		"revoked",
	).Inc()
}

func (ms *MetricsService) RecordIntermediateCACreated(customerTier int) {
	ms.intermediateCAsTotal.WithLabelValues(
		fmt.Sprintf("tier_%d", customerTier),
		"created",
	).Inc()
}

func (ms *MetricsService) RecordOCSPRequest(status string) {
	ms.ocspRequests.WithLabelValues(status).Inc()
}

func (ms *MetricsService) RecordAPIRequest(method, endpoint string, statusCode int) {
	status := "success"
	if statusCode >= 400 {
		status = "error"
	}
	
	ms.apiRequests.WithLabelValues(method, endpoint, status).Inc()
}

func (ms *MetricsService) RecordBackupSuccess() {
	ms.backupStatus.Set(1)
	ms.lastBackupTime.Set(float64(time.Now().Unix()))
}

func (ms *MetricsService) RecordBackupFailure() {
	ms.backupStatus.Set(0)
}