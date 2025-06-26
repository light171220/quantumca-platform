package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"quantumca-platform/internal/services"
	"quantumca-platform/internal/storage"
	"quantumca-platform/internal/utils"

	"github.com/gin-gonic/gin"
)

type AnalyticsHandler struct {
	db             *sql.DB
	config         *utils.Config
	logger         *utils.Logger
	metricsService *services.MetricsService
}

func NewAnalyticsHandler(db *sql.DB, config *utils.Config, logger *utils.Logger, metricsService *services.MetricsService) *AnalyticsHandler {
	return &AnalyticsHandler{
		db:             db,
		config:         config,
		logger:         logger,
		metricsService: metricsService,
	}
}

type DashboardResponse struct {
	Summary       DashboardSummary       `json:"summary"`
	CertificatesByStatus map[string]int   `json:"certificates_by_status"`
	AlgorithmUsage       []AlgorithmUsage `json:"algorithm_usage"`
	ExpirationTrends     []ExpirationTrend `json:"expiration_trends"`
	RecentActivity       []ActivityItem   `json:"recent_activity"`
	Timestamp            string           `json:"timestamp"`
}

type DashboardSummary struct {
	TotalCertificates    int `json:"total_certificates"`
	ActiveCertificates   int `json:"active_certificates"`
	ExpiringSoon         int `json:"expiring_soon"`
	RevokedCertificates  int `json:"revoked_certificates"`
	IntermediateCAs      int `json:"intermediate_cas"`
	DomainsValidated     int `json:"domains_validated"`
	CertificatesIssued24h int `json:"certificates_issued_24h"`
	CertificatesRevoked24h int `json:"certificates_revoked_24h"`
}

type AlgorithmUsage struct {
	Algorithm   string  `json:"algorithm"`
	Count       int     `json:"count"`
	Percentage  float64 `json:"percentage"`
	IsMultiPQC  bool    `json:"is_multi_pqc"`
}

type ExpirationTrend struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type ActivityItem struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
}

type ExpirationReportResponse struct {
	Overview     ExpirationOverview    `json:"overview"`
	ByTimeframe  []ExpirationTimeframe `json:"by_timeframe"`
	ByAlgorithm  []AlgorithmExpiration `json:"by_algorithm"`
	ByCustomer   []CustomerExpiration  `json:"by_customer"`
	Timestamp    string                `json:"timestamp"`
}

type ExpirationOverview struct {
	TotalCertificates    int `json:"total_certificates"`
	ExpiringNext7Days    int `json:"expiring_next_7_days"`
	ExpiringNext30Days   int `json:"expiring_next_30_days"`
	ExpiringNext90Days   int `json:"expiring_next_90_days"`
	ExpiredCertificates  int `json:"expired_certificates"`
}

type ExpirationTimeframe struct {
	Timeframe string `json:"timeframe"`
	Count     int    `json:"count"`
	Details   []ExpirationDetail `json:"details"`
}

type ExpirationDetail struct {
	CertificateID int    `json:"certificate_id"`
	CommonName    string `json:"common_name"`
	ExpiresAt     string `json:"expires_at"`
	DaysLeft      int    `json:"days_left"`
}

type AlgorithmExpiration struct {
	Algorithm string `json:"algorithm"`
	Total     int    `json:"total"`
	Expiring  int    `json:"expiring"`
}

type CustomerExpiration struct {
	CustomerID   int    `json:"customer_id"`
	CompanyName  string `json:"company_name"`
	Total        int    `json:"total"`
	Expiring     int    `json:"expiring"`
}

type RevocationStatsResponse struct {
	Overview         RevocationOverview    `json:"overview"`
	ReasonBreakdown  []RevocationReason    `json:"reason_breakdown"`
	TrendData        []RevocationTrend     `json:"trend_data"`
	MonthlyStats     []MonthlyRevocation   `json:"monthly_stats"`
	Timestamp        string                `json:"timestamp"`
}

type RevocationOverview struct {
	TotalRevoked       int     `json:"total_revoked"`
	RevokedLast7Days   int     `json:"revoked_last_7_days"`
	RevokedLast30Days  int     `json:"revoked_last_30_days"`
	RevocationRate     float64 `json:"revocation_rate"`
}

type RevocationReason struct {
	Reason      string  `json:"reason"`
	Code        int     `json:"code"`
	Count       int     `json:"count"`
	Percentage  float64 `json:"percentage"`
}

type RevocationTrend struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type MonthlyRevocation struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}

func (h *AnalyticsHandler) GetDashboard(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
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

	summary, err := h.getDashboardSummary(ctx, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get dashboard summary", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get dashboard data"})
		return
	}

	statusBreakdown, err := h.getCertificatesByStatus(ctx, custID)
	if err != nil {
		statusBreakdown = make(map[string]int)
	}

	algorithmUsage, err := h.getAlgorithmUsage(ctx, custID)
	if err != nil {
		algorithmUsage = []AlgorithmUsage{}
	}

	expirationTrends, err := h.getExpirationTrends(ctx, custID, 30)
	if err != nil {
		expirationTrends = []ExpirationTrend{}
	}

	recentActivity, err := h.getRecentActivity(ctx, custID, 10)
	if err != nil {
		recentActivity = []ActivityItem{}
	}

	response := &DashboardResponse{
		Summary:              *summary,
		CertificatesByStatus: statusBreakdown,
		AlgorithmUsage:       algorithmUsage,
		ExpirationTrends:     expirationTrends,
		RecentActivity:       recentActivity,
		Timestamp:            time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *AnalyticsHandler) GetExpirationReport(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
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

	overview, err := h.getExpirationOverview(ctx, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get expiration overview", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get expiration data"})
		return
	}

	byTimeframe, err := h.getExpirationByTimeframe(ctx, custID)
	if err != nil {
		byTimeframe = []ExpirationTimeframe{}
	}

	byAlgorithm, err := h.getExpirationByAlgorithm(ctx, custID)
	if err != nil {
		byAlgorithm = []AlgorithmExpiration{}
	}

	tier, _ := c.Get("tier")
	userTier, _ := tier.(int)
	
	var byCustomer []CustomerExpiration
	if userTier >= 3 {
		byCustomer, err = h.getExpirationByCustomer(ctx)
		if err != nil {
			byCustomer = []CustomerExpiration{}
		}
	}

	response := &ExpirationReportResponse{
		Overview:    *overview,
		ByTimeframe: byTimeframe,
		ByAlgorithm: byAlgorithm,
		ByCustomer:  byCustomer,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *AnalyticsHandler) GetAlgorithmUsage(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
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

	algorithmUsage, err := h.getAlgorithmUsage(ctx, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get algorithm usage", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get algorithm usage"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"algorithm_usage": algorithmUsage,
		"timestamp":       time.Now().Format(time.RFC3339),
	})
}

func (h *AnalyticsHandler) GetRevocationStats(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
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

	overview, err := h.getRevocationOverview(ctx, custID)
	if err != nil {
		h.logger.LogError(err, "Failed to get revocation overview", map[string]interface{}{
			"customer_id": custID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get revocation data"})
		return
	}

	reasonBreakdown, err := h.getRevocationReasonBreakdown(ctx, custID)
	if err != nil {
		reasonBreakdown = []RevocationReason{}
	}

	trendData, err := h.getRevocationTrends(ctx, custID, 30)
	if err != nil {
		trendData = []RevocationTrend{}
	}

	monthlyStats, err := h.getMonthlyRevocationStats(ctx, custID, 12)
	if err != nil {
		monthlyStats = []MonthlyRevocation{}
	}

	response := &RevocationStatsResponse{
		Overview:        *overview,
		ReasonBreakdown: reasonBreakdown,
		TrendData:       trendData,
		MonthlyStats:    monthlyStats,
		Timestamp:       time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (h *AnalyticsHandler) getDashboardSummary(ctx context.Context, customerID int) (*DashboardSummary, error) {
	query := `SELECT 
		COUNT(CASE WHEN status IN ('active', 'revoked', 'expired') THEN 1 END) as total,
		COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
		COUNT(CASE WHEN status = 'active' AND not_after <= ? THEN 1 END) as expiring_soon,
		COUNT(CASE WHEN status = 'revoked' THEN 1 END) as revoked,
		COUNT(CASE WHEN status = 'active' AND created_at >= ? THEN 1 END) as issued_24h,
		COUNT(CASE WHEN status = 'revoked' AND updated_at >= ? THEN 1 END) as revoked_24h
		FROM certificates WHERE customer_id = ?`
	
	now := time.Now()
	expiringSoonDate := now.AddDate(0, 0, 30)
	twentyFourHoursAgo := now.Add(-24 * time.Hour)
	
	var summary DashboardSummary
	err := h.db.QueryRowContext(ctx, query, expiringSoonDate, twentyFourHoursAgo, twentyFourHoursAgo, customerID).Scan(
		&summary.TotalCertificates,
		&summary.ActiveCertificates,
		&summary.ExpiringSoon,
		&summary.RevokedCertificates,
		&summary.CertificatesIssued24h,
		&summary.CertificatesRevoked24h,
	)
	
	domainsQuery := `SELECT COUNT(*) FROM domains WHERE customer_id = ? AND is_verified = true`
	h.db.QueryRowContext(ctx, domainsQuery, customerID).Scan(&summary.DomainsValidated)
	
	intermediateQuery := `SELECT COUNT(*) FROM intermediate_cas WHERE customer_id = ? AND status = 'active'`
	h.db.QueryRowContext(ctx, intermediateQuery, customerID).Scan(&summary.IntermediateCAs)
	
	return &summary, err
}

func (h *AnalyticsHandler) getCertificatesByStatus(ctx context.Context, customerID int) (map[string]int, error) {
	query := `SELECT status, COUNT(*) FROM certificates WHERE customer_id = ? GROUP BY status`
	
	rows, err := h.db.QueryContext(ctx, query, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	result := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		result[status] = count
	}
	
	return result, nil
}

func (h *AnalyticsHandler) getAlgorithmUsage(ctx context.Context, customerID int) ([]AlgorithmUsage, error) {
	query := `SELECT algorithms, is_multi_pqc, COUNT(*) as count 
			  FROM certificates 
			  WHERE customer_id = ? AND status = 'active' 
			  GROUP BY algorithms, is_multi_pqc 
			  ORDER BY count DESC`
	
	rows, err := h.db.QueryContext(ctx, query, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var usage []AlgorithmUsage
	var total int
	
	for rows.Next() {
		var algorithmsJSON string
		var isMultiPQC bool
		var count int
		
		if err := rows.Scan(&algorithmsJSON, &isMultiPQC, &count); err != nil {
			continue
		}
		
		algorithm := "unknown"
		if algorithmsJSON != "" {
			algorithm = algorithmsJSON
		}
		
		usage = append(usage, AlgorithmUsage{
			Algorithm:  algorithm,
			Count:      count,
			IsMultiPQC: isMultiPQC,
		})
		total += count
	}
	
	for i := range usage {
		if total > 0 {
			usage[i].Percentage = float64(usage[i].Count) / float64(total) * 100
		}
	}
	
	return usage, nil
}

func (h *AnalyticsHandler) getExpirationTrends(ctx context.Context, customerID, days int) ([]ExpirationTrend, error) {
	query := `SELECT DATE(not_after) as expiry_date, COUNT(*) as count 
			  FROM certificates 
			  WHERE customer_id = ? AND status = 'active' 
			  AND not_after BETWEEN ? AND ? 
			  GROUP BY DATE(not_after) 
			  ORDER BY expiry_date`
	
	now := time.Now()
	endDate := now.AddDate(0, 0, days)
	
	rows, err := h.db.QueryContext(ctx, query, customerID, now, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var trends []ExpirationTrend
	for rows.Next() {
		var date time.Time
		var count int
		
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		
		trends = append(trends, ExpirationTrend{
			Date:  date.Format("2006-01-02"),
			Count: count,
		})
	}
	
	return trends, nil
}

func (h *AnalyticsHandler) getRecentActivity(ctx context.Context, customerID, limit int) ([]ActivityItem, error) {
	query := `SELECT action, resource_id, details, created_at 
			  FROM audit_logs 
			  WHERE customer_id = ? 
			  ORDER BY created_at DESC 
			  LIMIT ?`
	
	rows, err := h.db.QueryContext(ctx, query, customerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var activities []ActivityItem
	for rows.Next() {
		var action, resourceID, detailsJSON string
		var createdAt time.Time
		
		if err := rows.Scan(&action, &resourceID, &detailsJSON, &createdAt); err != nil {
			continue
		}
		
		var details map[string]interface{}
		if detailsJSON != "" {
			if err := storage.UnmarshalJSON([]byte(detailsJSON), &details); err != nil {
				details = make(map[string]interface{})
			}
		} else {
			details = make(map[string]interface{})
		}
		
		activities = append(activities, ActivityItem{
			Type:        action,
			Description: h.formatActivityDescription(action, details),
			Timestamp:   createdAt.Format(time.RFC3339),
			Details:     details,
		})
	}
	
	return activities, nil
}

func (h *AnalyticsHandler) getExpirationOverview(ctx context.Context, customerID int) (*ExpirationOverview, error) {
	now := time.Now()
	
	query := `SELECT 
		COUNT(*) as total,
		COUNT(CASE WHEN not_after <= ? THEN 1 END) as expired,
		COUNT(CASE WHEN not_after > ? AND not_after <= ? THEN 1 END) as expiring_7d,
		COUNT(CASE WHEN not_after > ? AND not_after <= ? THEN 1 END) as expiring_30d,
		COUNT(CASE WHEN not_after > ? AND not_after <= ? THEN 1 END) as expiring_90d
		FROM certificates WHERE customer_id = ? AND status = 'active'`
	
	var overview ExpirationOverview
	err := h.db.QueryRowContext(ctx, query,
		now,
		now, now.AddDate(0, 0, 7),
		now, now.AddDate(0, 0, 30),
		now, now.AddDate(0, 0, 90),
		customerID,
	).Scan(
		&overview.TotalCertificates,
		&overview.ExpiredCertificates,
		&overview.ExpiringNext7Days,
		&overview.ExpiringNext30Days,
		&overview.ExpiringNext90Days,
	)
	
	return &overview, err
}

func (h *AnalyticsHandler) getExpirationByTimeframe(ctx context.Context, customerID int) ([]ExpirationTimeframe, error) {
	timeframes := []struct {
		name string
		days int
	}{
		{"Next 7 days", 7},
		{"Next 30 days", 30},
		{"Next 90 days", 90},
		{"Beyond 90 days", 0},
	}
	
	var result []ExpirationTimeframe
	now := time.Now()
	
	for _, tf := range timeframes {
		var query string
		var args []interface{}
		
		if tf.days == 0 {
			query = `SELECT id, common_name, not_after FROM certificates 
					 WHERE customer_id = ? AND status = 'active' AND not_after > ?
					 ORDER BY not_after LIMIT 50`
			args = []interface{}{customerID, now.AddDate(0, 0, 90)}
		} else {
			query = `SELECT id, common_name, not_after FROM certificates 
					 WHERE customer_id = ? AND status = 'active' 
					 AND not_after > ? AND not_after <= ?
					 ORDER BY not_after LIMIT 50`
			args = []interface{}{customerID, now, now.AddDate(0, 0, tf.days)}
		}
		
		rows, err := h.db.QueryContext(ctx, query, args...)
		if err != nil {
			continue
		}
		
		var details []ExpirationDetail
		for rows.Next() {
			var id int
			var commonName string
			var notAfter time.Time
			
			if err := rows.Scan(&id, &commonName, &notAfter); err != nil {
				continue
			}
			
			daysLeft := int(time.Until(notAfter).Hours() / 24)
			details = append(details, ExpirationDetail{
				CertificateID: id,
				CommonName:    commonName,
				ExpiresAt:     notAfter.Format(time.RFC3339),
				DaysLeft:      daysLeft,
			})
		}
		rows.Close()
		
		result = append(result, ExpirationTimeframe{
			Timeframe: tf.name,
			Count:     len(details),
			Details:   details,
		})
	}
	
	return result, nil
}

func (h *AnalyticsHandler) getExpirationByAlgorithm(ctx context.Context, customerID int) ([]AlgorithmExpiration, error) {
	now := time.Now()
	
	query := `SELECT algorithms, 
			  COUNT(*) as total,
			  COUNT(CASE WHEN not_after <= ? THEN 1 END) as expiring
			  FROM certificates 
			  WHERE customer_id = ? AND status = 'active'
			  GROUP BY algorithms`
	
	rows, err := h.db.QueryContext(ctx, query, now.AddDate(0, 0, 90), customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var result []AlgorithmExpiration
	for rows.Next() {
		var algorithmsJSON string
		var total, expiring int
		
		if err := rows.Scan(&algorithmsJSON, &total, &expiring); err != nil {
			continue
		}
		
		algorithm := "unknown"
		if algorithmsJSON != "" {
			algorithm = algorithmsJSON
		}
		
		result = append(result, AlgorithmExpiration{
			Algorithm: algorithm,
			Total:     total,
			Expiring:  expiring,
		})
	}
	
	return result, nil
}

func (h *AnalyticsHandler) getExpirationByCustomer(ctx context.Context) ([]CustomerExpiration, error) {
	now := time.Now()
	
	query := `SELECT c.customer_id, cu.company_name,
			  COUNT(*) as total,
			  COUNT(CASE WHEN c.not_after <= ? THEN 1 END) as expiring
			  FROM certificates c
			  JOIN customers cu ON c.customer_id = cu.id
			  WHERE c.status = 'active'
			  GROUP BY c.customer_id, cu.company_name
			  ORDER BY expiring DESC, total DESC
			  LIMIT 20`
	
	rows, err := h.db.QueryContext(ctx, query, now.AddDate(0, 0, 90))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var result []CustomerExpiration
	for rows.Next() {
		var customerID, total, expiring int
		var companyName string
		
		if err := rows.Scan(&customerID, &companyName, &total, &expiring); err != nil {
			continue
		}
		
		result = append(result, CustomerExpiration{
			CustomerID:  customerID,
			CompanyName: companyName,
			Total:       total,
			Expiring:    expiring,
		})
	}
	
	return result, nil
}

func (h *AnalyticsHandler) getRevocationOverview(ctx context.Context, customerID int) (*RevocationOverview, error) {
	now := time.Now()
	
	query := `SELECT 
		COUNT(CASE WHEN status = 'revoked' THEN 1 END) as total_revoked,
		COUNT(CASE WHEN status = 'revoked' AND updated_at >= ? THEN 1 END) as revoked_7d,
		COUNT(CASE WHEN status = 'revoked' AND updated_at >= ? THEN 1 END) as revoked_30d,
		COUNT(*) as total_certs
		FROM certificates WHERE customer_id = ?`
	
	var totalRevoked, revoked7d, revoked30d, totalCerts int
	err := h.db.QueryRowContext(ctx, query,
		now.AddDate(0, 0, -7),
		now.AddDate(0, 0, -30),
		customerID,
	).Scan(&totalRevoked, &revoked7d, &revoked30d, &totalCerts)
	
	if err != nil {
		return nil, err
	}
	
	revocationRate := 0.0
	if totalCerts > 0 {
		revocationRate = float64(totalRevoked) / float64(totalCerts) * 100
	}
	
	return &RevocationOverview{
		TotalRevoked:      totalRevoked,
		RevokedLast7Days:  revoked7d,
		RevokedLast30Days: revoked30d,
		RevocationRate:    revocationRate,
	}, nil
}

func (h *AnalyticsHandler) getRevocationReasonBreakdown(ctx context.Context, customerID int) ([]RevocationReason, error) {
	query := `SELECT revocation_reason, COUNT(*) as count 
			  FROM certificates 
			  WHERE customer_id = ? AND status = 'revoked' 
			  GROUP BY revocation_reason 
			  ORDER BY count DESC`
	
	rows, err := h.db.QueryContext(ctx, query, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	reasonNames := map[int]string{
		0: "Unspecified",
		1: "Key Compromise",
		2: "CA Compromise", 
		3: "Affiliation Changed",
		4: "Superseded",
		5: "Cessation of Operation",
		6: "Certificate Hold",
		8: "Remove from CRL",
		9: "Privilege Withdrawn",
		10: "AA Compromise",
	}
	
	var reasons []RevocationReason
	var total int
	
	for rows.Next() {
		var reasonCode, count int
		if err := rows.Scan(&reasonCode, &count); err != nil {
			continue
		}
		
		reasonName, exists := reasonNames[reasonCode]
		if !exists {
			reasonName = "Unknown"
		}
		
		reasons = append(reasons, RevocationReason{
			Reason: reasonName,
			Code:   reasonCode,
			Count:  count,
		})
		total += count
	}
	
	for i := range reasons {
		if total > 0 {
			reasons[i].Percentage = float64(reasons[i].Count) / float64(total) * 100
		}
	}
	
	return reasons, nil
}

func (h *AnalyticsHandler) getRevocationTrends(ctx context.Context, customerID, days int) ([]RevocationTrend, error) {
	query := `SELECT DATE(updated_at) as revoke_date, COUNT(*) as count 
			  FROM certificates 
			  WHERE customer_id = ? AND status = 'revoked' 
			  AND updated_at >= ? 
			  GROUP BY DATE(updated_at) 
			  ORDER BY revoke_date`
	
	startDate := time.Now().AddDate(0, 0, -days)
	
	rows, err := h.db.QueryContext(ctx, query, customerID, startDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var trends []RevocationTrend
	for rows.Next() {
		var date time.Time
		var count int
		
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		
		trends = append(trends, RevocationTrend{
			Date:  date.Format("2006-01-02"),
			Count: count,
		})
	}
	
	return trends, nil
}

func (h *AnalyticsHandler) getMonthlyRevocationStats(ctx context.Context, customerID, months int) ([]MonthlyRevocation, error) {
	query := `SELECT DATE_FORMAT(updated_at, '%Y-%m') as month, COUNT(*) as count 
			  FROM certificates 
			  WHERE customer_id = ? AND status = 'revoked' 
			  AND updated_at >= ? 
			  GROUP BY DATE_FORMAT(updated_at, '%Y-%m') 
			  ORDER BY month`
	
	startDate := time.Now().AddDate(0, -months, 0)
	
	rows, err := h.db.QueryContext(ctx, query, customerID, startDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var stats []MonthlyRevocation
	for rows.Next() {
		var month string
		var count int
		
		if err := rows.Scan(&month, &count); err != nil {
			continue
		}
		
		stats = append(stats, MonthlyRevocation{
			Month: month,
			Count: count,
		})
	}
	
	return stats, nil
}

func (h *AnalyticsHandler) formatActivityDescription(action string, details map[string]interface{}) string {
	switch action {
	case "certificate_issued":
		if commonName, ok := details["common_name"].(string); ok {
			return fmt.Sprintf("Certificate issued for %s", commonName)
		}
		return "Certificate issued"
	case "certificate_revoked":
		if commonName, ok := details["common_name"].(string); ok {
			return fmt.Sprintf("Certificate revoked for %s", commonName)
		}
		return "Certificate revoked"
	case "domain_verified":
		if domainName, ok := details["domain_name"].(string); ok {
			return fmt.Sprintf("Domain %s verified", domainName)
		}
		return "Domain verified"
	case "intermediate_ca_created":
		if commonName, ok := details["common_name"].(string); ok {
			return fmt.Sprintf("Intermediate CA created: %s", commonName)
		}
		return "Intermediate CA created"
	default:
		return action
	}
}