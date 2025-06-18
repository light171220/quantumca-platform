package utils

import (
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

func NewLogger(level string) *Logger {
	logger := logrus.New()
	
	logLevel, err := logrus.ParseLevel(strings.ToLower(level))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	
	logger.SetLevel(logLevel)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})
	
	logger.SetOutput(os.Stdout)
	
	return &Logger{Logger: logger}
}

func (l *Logger) LogCertificateEvent(event string, certID string, customerID int, details map[string]interface{}) {
	fields := logrus.Fields{
		"event":       event,
		"cert_id":     certID,
		"customer_id": customerID,
		"type":        "certificate_audit",
	}
	
	for k, v := range details {
		fields[k] = v
	}
	
	l.WithFields(fields).Info("Certificate lifecycle event")
}

func (l *Logger) LogSecurityEvent(event string, userID string, ip string, details map[string]interface{}) {
	fields := logrus.Fields{
		"event":   event,
		"user_id": userID,
		"ip":      ip,
		"type":    "security_audit",
	}
	
	for k, v := range details {
		fields[k] = v
	}
	
	l.WithFields(fields).Warn("Security event")
}

func (l *Logger) LogAPIAccess(method, path, ip string, statusCode int, duration time.Duration, userID string) {
	l.WithFields(logrus.Fields{
		"method":      method,
		"path":        path,
		"ip":          ip,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
		"user_id":     userID,
		"type":        "api_access",
	}).Info("API access")
}

func (l *Logger) LogError(err error, context string, fields map[string]interface{}) {
	logFields := logrus.Fields{
		"error":   err.Error(),
		"context": context,
		"type":    "error",
	}
	
	for k, v := range fields {
		logFields[k] = v
	}
	
	l.WithFields(logFields).Error("Application error")
}

func (l *Logger) Info(args ...interface{}) {
	l.Logger.Info(args...)
}

func (l *Logger) Error(args ...interface{}) {
	l.Logger.Error(args...)
}

func (l *Logger) Debug(args ...interface{}) {
	l.Logger.Debug(args...)
}

func (l *Logger) Warn(args ...interface{}) {
	l.Logger.Warn(args...)
}

func (l *Logger) Fatal(args ...interface{}) {
	l.Logger.Fatal(args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Warnf(format, args...)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logger.Fatalf(format, args...)
}

func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	return l.Logger.WithFields(fields)
}