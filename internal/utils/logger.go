package utils

import (
	"log"
	"os"
	"strings"
)

type Logger struct {
	level    LogLevel
	infoLog  *log.Logger
	errorLog *log.Logger
	debugLog *log.Logger
}

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	ERROR
)

func NewLogger(level string) *Logger {
	logLevel := INFO
	switch strings.ToLower(level) {
	case "debug":
		logLevel = DEBUG
	case "info":
		logLevel = INFO
	case "error":
		logLevel = ERROR
	}

	return &Logger{
		level:    logLevel,
		infoLog:  log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile),
		errorLog: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
		debugLog: log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
	}
}

func (l *Logger) Info(args ...interface{}) {
	if l.level <= INFO {
		l.infoLog.Println(args...)
	}
}

func (l *Logger) Error(args ...interface{}) {
	if l.level <= ERROR {
		l.errorLog.Println(args...)
	}
}

func (l *Logger) Debug(args ...interface{}) {
	if l.level <= DEBUG {
		l.debugLog.Println(args...)
	}
}

func (l *Logger) Fatal(args ...interface{}) {
	l.errorLog.Fatal(args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	if l.level <= INFO {
		l.infoLog.Printf(format, args...)
	}
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	if l.level <= ERROR {
		l.errorLog.Printf(format, args...)
	}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.level <= DEBUG {
		l.debugLog.Printf(format, args...)
	}
}