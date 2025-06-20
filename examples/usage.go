package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/dulguundd/logError-lib/errs"
	"github.com/dulguundd/logError-lib/logger"
	"net/http"

	"go.uber.org/zap"
)

func main() {
	// Initialize logger with configuration
	config := &logger.Config{
		Level:       "info",
		Format:      "json",
		Environment: "production",
		ServiceName: "user-service",
		Version:     "1.0.0",
	}

	err := logger.Initialize(config)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	// Ensure logs are flushed before program exits
	defer logger.Sync()

	// Example usage
	exampleErrorHandling()
	exampleContextualLogging()
	exampleSecurityLogging()
	exampleHTTPErrorHandling()
}

func exampleErrorHandling() {
	logger.Info("Starting error handling examples")

	// Create different types of errors
	notFoundErr := errs.NewNotFoundError("User not found")
	_ = errs.NewValidationError("Invalid email format")
	unexpectedErr := errs.NewUnexpectedError("Database connection failed")

	// Add context to errors
	dbErr := sql.ErrNoRows
	wrappedErr := errs.WrapError(dbErr, errs.CodeNotFound, "User lookup failed").
		WithRequestID("req-123")

	// Log errors appropriately
	logger.Error("Operation failed",
		zap.String("error_code", string(notFoundErr.Code)),
		zap.String("error_message", notFoundErr.Message),
		zap.String("request_id", notFoundErr.RequestID),
	)

	// Check error types
	if errs.IsAppError(wrappedErr) {
		if appErr, ok := errs.AsAppError(wrappedErr); ok {
			logger.Error("Application error occurred",
				zap.String("code", string(appErr.Code)),
				zap.String("message", appErr.Message),
				zap.Error(appErr.Cause),
			)
		}
	}

	// Use public version for client responses
	publicErr := unexpectedErr.AsPublic()
	logger.Info("Returning sanitized error to client",
		zap.Any("public_error", publicErr),
	)
}

func exampleContextualLogging() {
	// Create context with logging metadata
	ctx := context.Background()
	ctx = context.WithValue(ctx, logger.RequestIDKey, "req-12345")
	ctx = context.WithValue(ctx, logger.UserIDKey, "user-67890")
	ctx = context.WithValue(ctx, logger.TraceIDKey, "trace-abcdef")

	// Context-aware logging automatically includes metadata
	logger.InfoContext(ctx, "User action performed",
		zap.String("action", "profile_update"),
		zap.String("resource", "user_profile"),
	)

	// Audit logging with context
	logger.AuditLog("UPDATE", "user_profile",
		zap.String("user_id", "user-67890"),
		zap.String("field", "email"),
		zap.String("old_value", "[REDACTED]"),
		zap.String("new_value", "[REDACTED]"),
	)
}

func exampleSecurityLogging() {
	// Security event logging
	logger.SecurityEvent("Suspicious login attempt detected",
		zap.String("ip_address", "192.168.1.100"),
		zap.String("user_agent", "curl/7.68.0"),
		zap.Int("failed_attempts", 5),
	)

	// Sensitive data is automatically redacted
	logger.Info("User authentication",
		zap.String("username", "john.doe"),
		zap.String("password", "secret123"), // This will be redacted
		zap.String("api_key", "abc123"),     // This will be redacted
	)
}

func exampleHTTPErrorHandling() {
	// Simulate HTTP handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Add request ID to context
		requestID := r.Header.Get("X-Request-ID")
		if requestID != "" {
			ctx = context.WithValue(ctx, logger.RequestIDKey, requestID)
		}

		// Simulate business logic error
		user, err := getUserByID(ctx, "invalid-id")
		if err != nil {
			handleHTTPError(ctx, w, err)
			return
		}

		logger.InfoContext(ctx, "User retrieved successfully",
			zap.String("user_id", user.ID),
		)

		// Return successful response
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user_id": "%s"}`, user.ID)
	}

	// Example usage (this would be in your actual HTTP server setup)
	_ = handler
}

// User Simulate user service
type User struct {
	ID    string
	Email string
}

func getUserByID(ctx context.Context, userID string) (*User, error) {
	logger.DebugContext(ctx, "Fetching user by ID",
		zap.String("user_id", userID),
	)

	// Simulate validation
	if userID == "" {
		return nil, errs.NewValidationError("User ID is required")
	}

	if userID == "invalid-id" {
		return nil, errs.NewNotFoundError("User not found").
			WithRequestID(getRequestIDFromContext(ctx))
	}

	// Simulate database error
	if userID == "db-error" {
		dbErr := fmt.Errorf("connection timeout")
		return nil, errs.WrapError(dbErr, errs.CodeUnexpected, "Failed to query user database")
	}

	return &User{
		ID:    userID,
		Email: "user@example.com",
	}, nil
}

func handleHTTPError(ctx context.Context, w http.ResponseWriter, err error) {
	// Log the full error with context
	logger.ErrorContext(ctx, "HTTP request failed", zap.Error(err))

	// Handle different error types
	if appErr, ok := errs.AsAppError(err); ok {
		// Use the public version for client response
		publicErr := appErr.AsPublic()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.GetHTTPStatus())

		// In a real application, you'd use JSON marshaling
		fmt.Fprintf(w, `{"error": {"code": "%s", "message": "%s"}}`,
			publicErr.Code, publicErr.Message)
		return
	}

	// Handle unexpected errors
	logger.ErrorContext(ctx, "Unhandled error occurred", zap.Error(err))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, `{"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred"}}`)
}

func getRequestIDFromContext(ctx context.Context) string {
	if requestID := ctx.Value(logger.RequestIDKey); requestID != nil {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// RequestIDMiddleware Middleware for adding request ID to context
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			// Generate a new request ID if not provided
			requestID = generateRequestID()
		}

		ctx := context.WithValue(r.Context(), logger.RequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateRequestID() string {
	// In a real implementation, use a proper UUID library
	return fmt.Sprintf("req-%d", 12345)
}
