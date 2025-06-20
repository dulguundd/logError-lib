package logger

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *Logger
	once         sync.Once
)

// Logger wraps zap.Logger with additional functionality
type Logger struct {
	zap    *zap.Logger
	config *Config
}

// Config holds logger configuration
type Config struct {
	Level       string `json:"level" env:"LOG_LEVEL" default:"info"`
	Format      string `json:"format" env:"LOG_FORMAT" default:"json"` // json or console
	Environment string `json:"environment" env:"ENVIRONMENT" default:"production"`
	ServiceName string `json:"service_name" env:"SERVICE_NAME" default:"app"`
	Version     string `json:"version" env:"APP_VERSION" default:"unknown"`
}

// ContextKey represents keys used in context for logging
type ContextKey string

const (
	RequestIDKey ContextKey = "request_id"
	UserIDKey    ContextKey = "user_id"
	TraceIDKey   ContextKey = "trace_id"
)

// Initialize sets up the global logger with configuration
func Initialize(config *Config) error {
	var err error
	once.Do(func() {
		globalLogger, err = NewLogger(config)
	})
	return err
}

// NewLogger creates a new logger instance
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = &Config{
			Level:       getEnvOrDefault("LOG_LEVEL", "info"),
			Format:      getEnvOrDefault("LOG_FORMAT", "json"),
			Environment: getEnvOrDefault("ENVIRONMENT", "production"),
			ServiceName: getEnvOrDefault("SERVICE_NAME", "app"),
			Version:     getEnvOrDefault("APP_VERSION", "unknown"),
		}
	}

	zapConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(parseLogLevel(config.Level)),
		Development: config.Environment == "development",
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding: config.Format,
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		InitialFields: map[string]interface{}{
			"service": config.ServiceName,
			"version": config.Version,
		},
	}

	// Adjust config for development
	if config.Environment == "development" {
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		if config.Format == "console" {
			zapConfig.Encoding = "console"
		}
		zapConfig.DisableStacktrace = false
	} else {
		zapConfig.DisableStacktrace = true
	}

	logger, err := zapConfig.Build(zap.AddCallerSkip(1))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	return &Logger{
		zap:    logger,
		config: config,
	}, nil
}

// getEnvOrDefault gets environment variable or returns default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseLogLevel converts string to zap core.Level
func parseLogLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	case "panic":
		return zapcore.PanicLevel
	default:
		return zapcore.InfoLevel
	}
}

// WithContext extracts logging fields from context
func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := l.extractContextFields(ctx)
	if len(fields) == 0 {
		return l
	}

	return &Logger{
		zap:    l.zap.With(fields...),
		config: l.config,
	}
}

// extractContextFields extracts structured logging fields from context
func (l *Logger) extractContextFields(ctx context.Context) []zap.Field {
	var fields []zap.Field

	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		if id, ok := requestID.(string); ok && id != "" {
			fields = append(fields, zap.String("request_id", id))
		}
	}

	if userID := ctx.Value(UserIDKey); userID != nil {
		if id, ok := userID.(string); ok && id != "" {
			fields = append(fields, zap.String("user_id", id))
		}
	}

	if traceID := ctx.Value(TraceIDKey); traceID != nil {
		if id, ok := traceID.(string); ok && id != "" {
			fields = append(fields, zap.String("trace_id", id))
		}
	}

	return fields
}

// Structured logging methods

func (l *Logger) Debug(msg string, fields ...zap.Field) {
	l.zap.Debug(sanitizeLogMessage(msg), sanitizeFields(fields)...)
}

func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.zap.Info(sanitizeLogMessage(msg), sanitizeFields(fields)...)
}

func (l *Logger) Warn(msg string, fields ...zap.Field) {
	l.zap.Warn(sanitizeLogMessage(msg), sanitizeFields(fields)...)
}

func (l *Logger) Error(msg string, fields ...zap.Field) {
	l.zap.Error(sanitizeLogMessage(msg), sanitizeFields(fields)...)
}

func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	l.zap.Fatal(sanitizeLogMessage(msg), sanitizeFields(fields)...)
}

func (l *Logger) Panic(msg string, fields ...zap.Field) {
	l.zap.Panic(sanitizeLogMessage(msg), sanitizeFields(fields)...)
}

// Context-aware logging methods

func (l *Logger) DebugContext(ctx context.Context, msg string, fields ...zap.Field) {
	l.WithContext(ctx).Debug(msg, fields...)
}

func (l *Logger) InfoContext(ctx context.Context, msg string, fields ...zap.Field) {
	l.WithContext(ctx).Info(msg, fields...)
}

func (l *Logger) WarnContext(ctx context.Context, msg string, fields ...zap.Field) {
	l.WithContext(ctx).Warn(msg, fields...)
}

func (l *Logger) ErrorContext(ctx context.Context, msg string, fields ...zap.Field) {
	l.WithContext(ctx).Error(msg, fields...)
}

// Security-focused logging

func (l *Logger) SecurityEvent(msg string, fields ...zap.Field) {
	securityFields := append(fields, zap.String("event_type", "security"))
	l.zap.Warn(sanitizeLogMessage(msg), sanitizeFields(securityFields)...)
}

func (l *Logger) AuditLog(action, resource string, fields ...zap.Field) {
	auditFields := append(fields,
		zap.String("event_type", "audit"),
		zap.String("action", action),
		zap.String("resource", resource),
	)
	l.zap.Info("audit_event", sanitizeFields(auditFields)...)
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.zap.Sync()
}

// sanitizeLogMessage removes sensitive information from log messages
func sanitizeLogMessage(msg string) string {
	sensitive := []string{
		"password", "passwd", "pwd", "secret", "token", "key", "auth",
		"credential", "api_key", "private", "confidential",
	}

	lower := strings.ToLower(msg)
	for _, pattern := range sensitive {
		if strings.Contains(lower, pattern) {
			return "[REDACTED]"
		}
	}

	return msg
}

// sanitizeFields removes or masks sensitive information from log fields
func sanitizeFields(fields []zap.Field) []zap.Field {
	sensitiveKeys := map[string]bool{
		"password":      true,
		"passwd":        true,
		"pwd":           true,
		"secret":        true,
		"token":         true,
		"key":           true,
		"auth":          true,
		"credential":    true,
		"api_key":       true,
		"private_key":   true,
		"access_token":  true,
		"refresh_token": true,
	}

	sanitized := make([]zap.Field, 0, len(fields))
	for _, field := range fields {
		if sensitiveKeys[strings.ToLower(field.Key)] {
			sanitized = append(sanitized, zap.String(field.Key, "[REDACTED]"))
		} else {
			sanitized = append(sanitized, field)
		}
	}

	return sanitized
}

// GetLogger functions (for backward compatibility and convenience)
func GetLogger() *Logger {
	if globalLogger == nil {
		// Initialize with default config if not already initialized
		err := Initialize(nil)
		if err != nil {
			return nil
		}
	}
	return globalLogger
}

func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	GetLogger().Fatal(msg, fields...)
}

func Panic(msg string, fields ...zap.Field) {
	GetLogger().Panic(msg, fields...)
}

// Context-aware global functions

func DebugContext(ctx context.Context, msg string, fields ...zap.Field) {
	GetLogger().DebugContext(ctx, msg, fields...)
}

func InfoContext(ctx context.Context, msg string, fields ...zap.Field) {
	GetLogger().InfoContext(ctx, msg, fields...)
}

func WarnContext(ctx context.Context, msg string, fields ...zap.Field) {
	GetLogger().WarnContext(ctx, msg, fields...)
}

func ErrorContext(ctx context.Context, msg string, fields ...zap.Field) {
	GetLogger().ErrorContext(ctx, msg, fields...)
}

func SecurityEvent(msg string, fields ...zap.Field) {
	GetLogger().SecurityEvent(msg, fields...)
}

func AuditLog(action, resource string, fields ...zap.Field) {
	GetLogger().AuditLog(action, resource, fields...)
}

func Sync() error {
	return GetLogger().Sync()
}
