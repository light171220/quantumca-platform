package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/api/handlers"
	"quantumca-platform/internal/api/middleware"
	"quantumca-platform/internal/ocsp"
	"quantumca-platform/internal/services"
	"quantumca-platform/internal/utils"
	"quantumca-platform/web"
)

type Server struct {
	db                *sql.DB
	config            *utils.Config
	logger            *utils.Logger
	engine            *gin.Engine
	httpServer        *http.Server
	ocspServer        *ocsp.Server
	lifecycleService  *services.LifecycleService
	backupService     *services.BackupService
	metricsService    *services.MetricsService
	healthService     *services.HealthService
}

func NewServer(db *sql.DB, config *utils.Config, logger *utils.Logger) (*Server, error) {
	if config == nil || db == nil || logger == nil {
		return nil, fmt.Errorf("required dependencies cannot be nil")
	}

	if config.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}
	
	engine := gin.New()
	
	lifecycleService := services.NewLifecycleService(db, config, logger)
	backupService := services.NewBackupService(config, logger)
	metricsService := services.NewMetricsService(db, config, logger)
	healthService := services.NewHealthService(db, config, logger)
	ocspServer := ocsp.NewServer(db, config)
	
	server := &Server{
		db:               db,
		config:           config,
		logger:           logger,
		engine:           engine,
		ocspServer:       ocspServer,
		lifecycleService: lifecycleService,
		backupService:    backupService,
		metricsService:   metricsService,
		healthService:    healthService,
	}

	if err := server.setupMiddleware(); err != nil {
		return nil, fmt.Errorf("failed to setup middleware: %w", err)
	}

	if err := server.setupRoutes(); err != nil {
		return nil, fmt.Errorf("failed to setup routes: %w", err)
	}

	server.httpServer = &http.Server{
		Addr:           fmt.Sprintf(":%d", config.APIPort),
		Handler:        engine,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		IdleTimeout:    config.IdleTimeout,
		MaxHeaderBytes: 1 << 20,
	}
	
	if err := server.startBackgroundServices(); err != nil {
		return nil, fmt.Errorf("failed to start background services: %w", err)
	}
	
	return server, nil
}

func (s *Server) setupMiddleware() error {
	s.engine.Use(gin.Recovery())
	s.engine.Use(middleware.SecurityHeaders())
	s.engine.Use(middleware.CORSMiddleware())
	s.engine.Use(middleware.AuditLog(s.logger))

	middleware.InitRateLimiter(s.config.APIRateLimit)
	s.engine.Use(middleware.RateLimit(s.config.APIRateLimit))
	s.engine.Use(middleware.RequestSizeLimit(s.config.MaxRequestSize))

	s.engine.Use(func(c *gin.Context) {
		c.Set("request_id", utils.GenerateRequestID())
		c.Header("X-Request-ID", c.GetString("request_id"))
		c.Next()
	})

	return nil
}

func (s *Server) setupRoutes() error {
	s.engine.Static("/static", "./web/static")
	s.engine.LoadHTMLGlob("web/templates/*")

	webHandler := web.NewHandler(s.db, s.config, s.logger)
	if webHandler == nil {
		return fmt.Errorf("failed to create web handler")
	}

	s.setupWebRoutes(webHandler)
	s.setupAPIRoutes()
	s.setupHealthRoutes()

	s.engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":      "Endpoint not found",
			"path":       c.Request.URL.Path,
			"method":     c.Request.Method,
			"request_id": c.GetString("request_id"),
		})
	})

	return nil
}

func (s *Server) setupWebRoutes(webHandler *web.Handler) {
	web := s.engine.Group("/")
	web.Use(middleware.SecurityHeaders())
	{
		web.GET("/", webHandler.Dashboard)
		web.GET("/dashboard", webHandler.Dashboard)
		web.GET("/certificates", webHandler.Certificates)
		web.GET("/issue-cert", webHandler.IssueCert)
		web.GET("/customers", webHandler.Customers)
		web.GET("/intermediate-ca", webHandler.IntermediateCA)
	}
}

func (s *Server) setupAPIRoutes() {
	api := s.engine.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.Next()
	})

	authHandler := handlers.NewAuthHandler(s.db, s.config, s.logger)
	api.POST("/auth/login", authHandler.Login)
	api.POST("/auth/refresh", authHandler.RefreshToken)

	customerHandler := handlers.NewCustomerHandler(s.db, s.config, s.logger, s.metricsService)
	api.POST("/customers", customerHandler.Create)
	
	protected := api.Group("")
	protected.Use(middleware.APIKeyAuth(s.db, s.logger))
	{
		protected.GET("/customers/:id", customerHandler.Get)
		protected.PUT("/customers/:id", customerHandler.Update)

		domainHandler := handlers.NewDomainHandler(s.db, s.config, s.logger)
		protected.POST("/domains", domainHandler.Add)
		protected.POST("/domains/:id/verify", domainHandler.Verify)
		protected.GET("/domains", domainHandler.List)
		protected.DELETE("/domains/:id", domainHandler.Delete)

		certHandler := handlers.NewCertificateHandler(s.db, s.config, s.logger, s.metricsService)
		protected.POST("/certificates", certHandler.Issue)
		protected.GET("/certificates", certHandler.List)
		protected.GET("/certificates/:id", certHandler.Get)
		protected.POST("/certificates/:id/revoke", certHandler.Revoke)
		protected.POST("/certificates/:id/renew", certHandler.Renew)
		protected.GET("/certificates/:id/download", certHandler.Download)

		intermediateHandler := handlers.NewIntermediateHandler(s.db, s.config, s.logger, s.metricsService)
		tier2Required := protected.Group("")
		tier2Required.Use(middleware.RequireTier(2))
		{
			tier2Required.POST("/intermediate-ca", intermediateHandler.Create)
			tier2Required.GET("/intermediate-ca", intermediateHandler.List)
			tier2Required.GET("/intermediate-ca/:id", intermediateHandler.Get)
			tier2Required.DELETE("/intermediate-ca/:id", intermediateHandler.Revoke)
		}

		templateHandler := handlers.NewTemplateHandler(s.db, s.config, s.logger)
		protected.GET("/templates", templateHandler.List)
		protected.GET("/templates/:id", templateHandler.Get)

		lifecycleHandler := handlers.NewLifecycleHandler(s.lifecycleService, s.logger)
		protected.GET("/certificates/:id/status", lifecycleHandler.GetStatus)
		protected.POST("/certificates/bulk-renew", lifecycleHandler.BulkRenew)

		auditHandler := handlers.NewAuditHandler(s.db, s.config, s.logger)
		protected.GET("/audit-logs", auditHandler.List)
		protected.GET("/audit-logs/:id", auditHandler.Get)
	}
}

func (s *Server) setupHealthRoutes() {
	health := s.engine.Group("/health")
	{
		healthHandler := handlers.NewHealthHandler(s.db, s.config, s.logger)
		health.GET("/", healthHandler.Check)
		health.GET("/live", healthHandler.Liveness)
		health.GET("/ready", healthHandler.Readiness)
		health.GET("/metrics", healthHandler.Metrics)
	}

	s.engine.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service":    "quantumca-platform",
			"version":    "1.0.0",
			"build":      os.Getenv("BUILD_VERSION"),
			"commit":     os.Getenv("GIT_COMMIT"),
			"build_time": os.Getenv("BUILD_TIME"),
			"go_version": os.Getenv("GO_VERSION"),
		})
	})
}

func (s *Server) startBackgroundServices() error {
	if err := s.lifecycleService.Start(); err != nil {
		return fmt.Errorf("failed to start lifecycle service: %w", err)
	}

	if s.config.BackupEnabled {
		if err := s.backupService.Start(); err != nil {
			return fmt.Errorf("failed to start backup service: %w", err)
		}
	}

	if s.config.MetricsEnabled {
		if err := s.metricsService.Start(); err != nil {
			return fmt.Errorf("failed to start metrics service: %w", err)
		}
	}

	if err := s.healthService.Start(); err != nil {
		return fmt.Errorf("failed to start health service: %w", err)
	}

	return nil
}

func (s *Server) Start() error {
	s.logger.Infof("Starting QuantumCA Platform server on port %d", s.config.APIPort)
	s.logger.Infof("Environment: %s", s.config.Environment)
	s.logger.Infof("TLS Enabled: %v", s.config.TLSEnabled)
	s.logger.Infof("Debug Mode: %v", gin.IsDebugging())

	go func() {
		s.logger.Infof("Starting OCSP server on port %d", s.config.OCSPPort)
		if err := s.ocspServer.Start(); err != nil {
			s.logger.LogError(err, "OCSP server failed to start", nil)
		}
	}()

	go s.handleShutdown()

	if s.config.TLSEnabled {
		if s.config.TLSCertPath == "" || s.config.TLSKeyPath == "" {
			return fmt.Errorf("TLS enabled but certificate or key path not configured")
		}
		s.logger.Infof("Starting HTTPS server with TLS")
		return s.httpServer.ListenAndServeTLS(s.config.TLSCertPath, s.config.TLSKeyPath)
	}

	s.logger.Warn("Starting HTTP server without TLS - not recommended for production")
	return s.httpServer.ListenAndServe()
}

func (s *Server) handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	
	sig := <-sigChan
	s.logger.Infof("Received signal %v, initiating graceful shutdown", sig)
	
	if err := s.Shutdown(); err != nil {
		s.logger.Errorf("Error during shutdown: %v", err)
		os.Exit(1)
	}
	
	s.logger.Info("Server shutdown completed successfully")
	os.Exit(0)
}

func (s *Server) Shutdown() error {
	s.logger.Info("Shutting down QuantumCA Platform server")

	ctx, cancel := context.WithTimeout(context.Background(), s.config.GracefulShutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Errorf("HTTP server shutdown error: %v", err)
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	s.logger.Info("HTTP server stopped")

	if err := s.stopBackgroundServices(); err != nil {
		s.logger.Errorf("Background services shutdown error: %v", err)
		return fmt.Errorf("background services shutdown failed: %w", err)
	}

	if err := s.db.Close(); err != nil {
		s.logger.Errorf("Database close error: %v", err)
		return fmt.Errorf("database close failed: %w", err)
	}

	s.logger.Info("Database connections closed")
	return nil
}

func (s *Server) stopBackgroundServices() error {
	var errors []error

	if err := s.lifecycleService.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("lifecycle service stop failed: %w", err))
	}

	if s.config.BackupEnabled {
		if err := s.backupService.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("backup service stop failed: %w", err))
		}
	}

	if s.config.MetricsEnabled {
		if err := s.metricsService.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("metrics service stop failed: %w", err))
		}
	}

	if err := s.healthService.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("health service stop failed: %w", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("multiple service stop errors: %v", errors)
	}

	return nil
}

func (s *Server) GetConfig() *utils.Config {
	return s.config
}

func (s *Server) GetLogger() *utils.Logger {
	return s.logger
}

func (s *Server) GetDatabase() *sql.DB {
	return s.db
}

func (s *Server) GetMetricsService() *services.MetricsService {
	return s.metricsService
}