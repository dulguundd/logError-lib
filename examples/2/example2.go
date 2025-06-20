package main

import (
	"context"
	"fmt"
	"github.com/dulguundd/logError-lib/errs"
	"github.com/dulguundd/logError-lib/logger"
	"time"

	"go.uber.org/zap"
)

func main() {
	// Example 1: Basic Logger Setup and Usage
	fmt.Println("=== Example 1: Basic Logger Setup ===")
	basicLoggingExample()

	fmt.Println("\n=== Example 2: Different Log Levels ===")
	logLevelsExample()

	fmt.Println("\n=== Example 3: Structured Logging ===")
	structuredLoggingExample()

	fmt.Println("\n=== Example 4: Context-Aware Logging ===")
	contextLoggingExample()

	fmt.Println("\n=== Example 5: Security and Audit Logging ===")
	securityLoggingExample()

	fmt.Println("\n=== Example 6: Error Integration ===")
	errorIntegrationExample()

	fmt.Println("\n=== Example 7: Development vs Production ===")
	environmentExample()
}

func basicLoggingExample() {
	// Initialize logger with basic configuration
	config := &logger.Config{
		Level:       "info",
		Format:      "json",
		Environment: "production",
		ServiceName: "user-service",
		Version:     "1.2.3",
	}

	logger.Initialize(config)
	defer logger.Sync()

	// Simple logging
	logger.Info("Service started successfully")
	logger.Error("Failed to connect to database")

	/* OUTPUT (JSON format):
	{"level":"info","timestamp":"2025-06-20T10:30:45.123Z","caller":"main.go:45","message":"Service started successfully","service":"user-service","version":"1.2.3"}
	{"level":"error","timestamp":"2025-06-20T10:30:45.124Z","caller":"main.go:46","message":"Failed to connect to database","service":"user-service","version":"1.2.3"}
	*/
}

func logLevelsExample() {
	logger.Debug("Debug message - detailed info") // Won't show if level is info+
	logger.Info("Info message - general information")
	logger.Warn("Warning message - something suspicious")
	logger.Error("Error message - something went wrong")

	/* OUTPUT:
	{"level":"info","timestamp":"2025-06-20T10:30:45.125Z","caller":"main.go:52","message":"Info message - general information","service":"user-service","version":"1.2.3"}
	{"level":"warn","timestamp":"2025-06-20T10:30:45.126Z","caller":"main.go:53","message":"Warning message - something suspicious","service":"user-service","version":"1.2.3"}
	{"level":"error","timestamp":"2025-06-20T10:30:45.127Z","caller":"main.go:54","message":"Error message - something went wrong","service":"user-service","version":"1.2.3"}
	*/
}

func structuredLoggingExample() {
	// Logging with structured fields
	logger.Info("User login attempt",
		zap.String("user_id", "user-12345"),
		zap.String("ip_address", "192.168.1.100"),
		zap.Duration("response_time", 250*time.Millisecond),
		zap.Bool("success", true),
		zap.Int("attempt_count", 1),
	)

	logger.Error("Database query failed",
		zap.String("query", "SELECT * FROM users WHERE id = ?"),
		zap.String("table", "users"),
		zap.Duration("timeout", 30*time.Second),
		zap.Int("retry_count", 3),
	)

	/* OUTPUT:
	{"level":"info","timestamp":"2025-06-20T10:30:45.128Z","caller":"main.go:65","message":"User login attempt","service":"user-service","version":"1.2.3","user_id":"user-12345","ip_address":"192.168.1.100","response_time":0.25,"success":true,"attempt_count":1}
	{"level":"error","timestamp":"2025-06-20T10:30:45.129Z","caller":"main.go:72","message":"Database query failed","service":"user-service","version":"1.2.3","query":"SELECT * FROM users WHERE id = ?","table":"users","timeout":30,"retry_count":3}
	*/
}

func contextLoggingExample() {
	// Create context with logging metadata
	ctx := context.Background()
	ctx = context.WithValue(ctx, logger.RequestIDKey, "req-abc123")
	ctx = context.WithValue(ctx, logger.UserIDKey, "user-67890")
	ctx = context.WithValue(ctx, logger.TraceIDKey, "trace-xyz789")

	// Context-aware logging automatically includes metadata
	logger.InfoContext(ctx, "Processing user request",
		zap.String("action", "get_profile"),
		zap.String("endpoint", "/api/v1/user/profile"),
	)

	logger.ErrorContext(ctx, "Authorization failed",
		zap.String("reason", "invalid_token"),
		zap.String("token_type", "bearer"),
	)

	/* OUTPUT:
	{"level":"info","timestamp":"2025-06-20T10:30:45.130Z","caller":"main.go:88","message":"Processing user request","service":"user-service","version":"1.2.3","request_id":"req-abc123","user_id":"user-67890","trace_id":"trace-xyz789","action":"get_profile","endpoint":"/api/v1/user/profile"}
	{"level":"error","timestamp":"2025-06-20T10:30:45.131Z","caller":"main.go:93","message":"Authorization failed","service":"user-service","version":"1.2.3","request_id":"req-abc123","user_id":"user-67890","trace_id":"trace-xyz789","reason":"invalid_token","token_type":"bearer"}
	*/
}

func securityLoggingExample() {
	// Security event logging
	logger.SecurityEvent("Multiple failed login attempts detected",
		zap.String("user_id", "user-12345"),
		zap.String("ip_address", "192.168.1.100"),
		zap.Int("failed_attempts", 5),
		zap.Duration("time_window", 10*time.Minute),
	)

	// Audit logging
	logger.AuditLog("UPDATE", "user_profile",
		zap.String("user_id", "user-67890"),
		zap.String("admin_id", "admin-001"),
		zap.String("field_changed", "email"),
		zap.String("old_value", "old@example.com"),
		zap.String("new_value", "new@example.com"),
	)

	// Sensitive data demonstration (automatically redacted)
	logger.Info("User registration attempt",
		zap.String("username", "johndoe"),
		zap.String("email", "john@example.com"),
		zap.String("password", "secretpassword123"), // Will be redacted
		zap.String("api_key", "sk-1234567890"),      // Will be redacted
	)

	/* OUTPUT:
	{"level":"warn","timestamp":"2025-06-20T10:30:45.132Z","caller":"main.go:101","message":"Multiple failed login attempts detected","service":"user-service","version":"1.2.3","event_type":"security","user_id":"user-12345","ip_address":"192.168.1.100","failed_attempts":5,"time_window":600}
	{"level":"info","timestamp":"2025-06-20T10:30:45.133Z","caller":"main.go:108","message":"audit_event","service":"user-service","version":"1.2.3","event_type":"audit","action":"UPDATE","resource":"user_profile","user_id":"user-67890","admin_id":"admin-001","field_changed":"email","old_value":"old@example.com","new_value":"new@example.com"}
	{"level":"info","timestamp":"2025-06-20T10:30:45.134Z","caller":"main.go:117","message":"User registration attempt","service":"user-service","version":"1.2.3","username":"johndoe","email":"john@example.com","password":"[REDACTED]","api_key":"[REDACTED]"}
	*/
}

func errorIntegrationExample() {
	// Create different types of errors
	notFoundErr := errs.NewNotFoundError("User not found").WithRequestID("req-123")
	_ = errs.NewValidationError("Invalid email format")

	// Log errors with full context
	logger.Error("User lookup failed",
		zap.String("error_code", string(notFoundErr.Code)),
		zap.String("error_message", notFoundErr.Message),
		zap.String("request_id", notFoundErr.RequestID),
		zap.Time("error_timestamp", notFoundErr.Timestamp),
	)

	// Wrap and log external errors
	externalErr := fmt.Errorf("database connection timeout")
	wrappedErr := errs.WrapError(externalErr, errs.CodeUnexpected, "Failed to query database")

	logger.Error("Database operation failed",
		zap.String("operation", "SELECT"),
		zap.Error(wrappedErr),
		zap.String("app_error_code", string(wrappedErr.Code)),
	)

	/* OUTPUT:
	{"level":"error","timestamp":"2025-06-20T10:30:45.135Z","caller":"main.go:138","message":"User lookup failed","service":"user-service","version":"1.2.3","error_code":"NOT_FOUND","error_message":"User not found","request_id":"req-123","error_timestamp":"2025-06-20T10:30:45.135Z"}
	{"level":"error","timestamp":"2025-06-20T10:30:45.136Z","caller":"main.go:145","message":"Database operation failed","service":"user-service","version":"1.2.3","operation":"SELECT","error":"[INTERNAL_ERROR] Failed to query database: database connection timeout","app_error_code":"INTERNAL_ERROR"}
	*/
}

func environmentExample() {
	fmt.Println("--- Development Environment Output ---")

	// Development configuration
	devConfig := &logger.Config{
		Level:       "debug",
		Format:      "console",
		Environment: "development",
		ServiceName: "user-service",
		Version:     "dev",
	}

	devLogger, _ := logger.NewLogger(devConfig)

	devLogger.Debug("Debug info in development")
	devLogger.Info("User authenticated successfully",
		zap.String("user_id", "user-123"),
		zap.String("method", "oauth2"),
	)
	devLogger.Error("Validation failed",
		zap.String("field", "email"),
		zap.String("value", "invalid-email"),
	)

	/* DEVELOPMENT OUTPUT (Console format with colors):
	2025-06-20T10:30:45.137Z	DEBUG	main.go:165	Debug info in development	{"service": "user-service", "version": "dev"}
	2025-06-20T10:30:45.138Z	INFO	main.go:166	User authenticated successfully	{"service": "user-service", "version": "dev", "user_id": "user-123", "method": "oauth2"}
	2025-06-20T10:30:45.139Z	ERROR	main.go:170	Validation failed	{"service": "user-service", "version": "dev", "field": "email", "value": "invalid-email"}
	*/

	fmt.Println("\n--- Production Environment Output ---")

	// Production configuration
	prodConfig := &logger.Config{
		Level:       "info",
		Format:      "json",
		Environment: "production",
		ServiceName: "user-service",
		Version:     "1.2.3",
	}

	prodLogger, _ := logger.NewLogger(prodConfig)

	prodLogger.Debug("Debug info in production") // Won't show
	prodLogger.Info("User authenticated successfully",
		zap.String("user_id", "user-123"),
		zap.String("method", "oauth2"),
	)
	prodLogger.Error("Validation failed",
		zap.String("field", "email"),
		zap.String("value", "invalid-email"),
	)

	/* PRODUCTION OUTPUT (JSON format, no debug):
	{"level":"info","timestamp":"2025-06-20T10:30:45.140Z","caller":"main.go:187","message":"User authenticated successfully","service":"user-service","version":"1.2.3","user_id":"user-123","method":"oauth2"}
	{"level":"error","timestamp":"2025-06-20T10:30:45.141Z","caller":"main.go:191","message":"Validation failed","service":"user-service","version":"1.2.3","field":"email","value":"invalid-email"}
	*/
}

// HTTP Handler Example
func httpHandlerExample() {
	// This would be used in your HTTP handlers
	ctx := context.Background()
	ctx = context.WithValue(ctx, logger.RequestIDKey, "req-http-001")

	// Log incoming request
	logger.InfoContext(ctx, "HTTP request received",
		zap.String("method", "POST"),
		zap.String("path", "/api/v1/users"),
		zap.String("user_agent", "curl/7.68.0"),
		zap.String("remote_addr", "192.168.1.100"),
	)

	// Simulate processing
	start := time.Now()

	// Log processing steps
	logger.DebugContext(ctx, "Validating request payload")
	logger.DebugContext(ctx, "Querying database")

	// Log response
	duration := time.Since(start)
	logger.InfoContext(ctx, "HTTP request completed",
		zap.Int("status_code", 201),
		zap.Duration("duration", duration),
		zap.String("response_size", "156 bytes"),
	)

	/* OUTPUT:
	{"level":"info","timestamp":"2025-06-20T10:30:45.142Z","caller":"main.go:203","message":"HTTP request received","service":"user-service","version":"1.2.3","request_id":"req-http-001","method":"POST","path":"/api/v1/users","user_agent":"curl/7.68.0","remote_addr":"192.168.1.100"}
	{"level":"info","timestamp":"2025-06-20T10:30:45.143Z","caller":"main.go:215","message":"HTTP request completed","service":"user-service","version":"1.2.3","request_id":"req-http-001","status_code":201,"duration":0.001,"response_size":"156 bytes"}
	*/
}
