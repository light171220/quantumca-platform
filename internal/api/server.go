package api

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"quantumca-platform/internal/api/handlers"
	"quantumca-platform/internal/api/middleware"
	"quantumca-platform/internal/utils"
	"quantumca-platform/web"
)

type Server struct {
	db     *sql.DB
	config *utils.Config
	logger *utils.Logger
	engine *gin.Engine
}

func NewServer(db *sql.DB, config *utils.Config, logger *utils.Logger) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	
	server := &Server{
		db:     db,
		config: config,
		logger: logger,
		engine: engine,
	}

	server.setupMiddleware()
	server.setupRoutes()
	
	return server
}

func (s *Server) setupMiddleware() {
	s.engine.Use(gin.Recovery())
	s.engine.Use(middleware.Logger(s.logger))
	s.engine.Use(middleware.CORS())
}

func (s *Server) setupRoutes() {
	s.engine.Static("/static", "./web/static")
	s.engine.LoadHTMLGlob("web/templates/*")

	webHandler := web.NewHandler(s.db, s.config, s.logger)
	s.engine.GET("/", webHandler.Dashboard)
	s.engine.GET("/dashboard", webHandler.Dashboard)
	s.engine.GET("/certificates", webHandler.Certificates)
	s.engine.GET("/issue-cert", webHandler.IssueCert)
	s.engine.GET("/customers", webHandler.Customers)
	s.engine.GET("/intermediate-ca", webHandler.IntermediateCA)

	api := s.engine.Group("/api/v1")
	{
		customerHandler := handlers.NewCustomerHandler(s.db, s.config, s.logger)
		api.POST("/customers", customerHandler.Create)
		api.GET("/customers/:id", customerHandler.Get)

		domainHandler := handlers.NewDomainHandler(s.db, s.config, s.logger)
		api.POST("/domains", domainHandler.Add)
		api.POST("/domains/:id/verify", domainHandler.Verify)

		certHandler := handlers.NewCertificateHandler(s.db, s.config, s.logger)
		api.POST("/certificates", certHandler.Issue)
		api.GET("/certificates", certHandler.List)
		api.GET("/certificates/:id", certHandler.Get)
		api.POST("/certificates/:id/revoke", certHandler.Revoke)

		intermediateHandler := handlers.NewIntermediateHandler(s.db, s.config, s.logger)
		api.POST("/intermediate-ca", intermediateHandler.Create)
		api.GET("/intermediate-ca/:id", intermediateHandler.Get)

		healthHandler := handlers.NewHealthHandler(s.db, s.config, s.logger)
		api.GET("/health", healthHandler.Check)
	}

	s.engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"service": "quantumca-platform",
		})
	})
}

func (s *Server) Start(addr string) error {
	return s.engine.Run(addr)
}