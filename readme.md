# Go Logging and Error Handling Library

A secure, production-ready logging and error handling library for Go applications with built-in security features, context propagation, and comprehensive error management.

## Features

### 🛡️ Security-First Design
- **Automatic Sensitive Data Redaction**: Passwords, tokens, API keys automatically masked
- **Information Disclosure Prevention**: Error messages sanitized to prevent data leaks
- **Security Event Logging**: Dedicated methods for security and audit events
- **Stack Trace Management**: Full traces in development, sanitized in production

### 📊 Structured Logging
- **JSON/Console Output**: Machine-readable JSON for production, human-friendly console for development
- **Context Propagation**: Request ID, User ID, and Trace ID automatically included
- **Environment-Aware**: Different configurations for development, staging, and production
- **Performance Optimized**: Zero-allocation logging in hot paths

### 🔧 Error Management
- **Structured Errors**: Custom error codes with HTTP status mapping
- **Error Wrapping**: Go 1.13+ compatible error wrapping with full context
- **Public/Private Separation**: Internal error details separate from client responses
- **Request Tracing**: Automatic correlation between errors and requests

## Quick Start

### Installation

```bash
go get github.com/yourusername/your-logging-lib
```

### Basic Usage

```go
package main

import (
    "context"
    "go.uber.org/zap"
    
    "github.com/dulguundd/logError-lib/logger"
    "github.com/dulguundd/logError-lib/errs"
)

func main() {
    // Initialize logger
    config := &logger.Config{
        Level:       "info",
        Format:      "json",
        Environment: "production",
        ServiceName: "user-service",
        Version:     "1.0.0",
    }
    
    err := logger.Initialize(config)
    if err != nil {
        panic(err)
    }
    defer logger.Sync()
    
    // Basic logging
    logger.Info("Service started successfully")
    
    // Structured logging
    logger.Info("User action", 
        zap.String("user_id", "123"),
        zap.String("action", "login"),
    )
    
    // Context-aware logging
    ctx := context.WithValue(context.Background(), logger.RequestIDKey, "req-123")
    logger.InfoContext(ctx, "Processing request")
    
    // Error handling
    err = processUser("invalid-id")
    if err != nil {
        if appErr, ok := errs.AsAppError(err); ok {
            logger.Error("Application error", 
                zap.String("code", string(appErr.Code)),
                zap.Error(err),
            )
        }
    }
}

func processUser(userID string) error {
    if userID == "" {
        return errs.NewValidationError("User ID is required")
    }
    
    if userID == "invalid-id" {
        return errs.NewNotFoundError("User not found")
    }
    
    return nil
}
```

## Configuration

### Environment Variables

The logger can be configured using environment variables:

```bash
export LOG_LEVEL=info
export LOG_FORMAT=json
export ENVIRONMENT=production
export SERVICE_NAME=user-service
export APP_VERSION=1.0.0
```

### Configuration Options

```go
type Config struct {
    Level       string // debug, info, warn, error, fatal, panic
    Format      string // json, console
    Environment string // development, staging, production
    ServiceName string // Your service name
    Version     string // Application version
}
```

### Development vs Production

**Development Configuration:**
```go
config := &logger.Config{
    Level:       "debug",
    Format:      "console",
    Environment: "development",
    ServiceName: "my-service",
    Version:     "dev",
}
```

**Production Configuration:**
```go
config := &logger.Config{
    Level:       "info", 
    Format:      "json",
    Environment: "production",
    ServiceName: "my-service",
    Version:     "1.0.0",
}
```

## Usage Examples

### Context-Aware Logging

```go
// Add request context
ctx := context.Background()
ctx = context.WithValue(ctx, logger.RequestIDKey, "req-12345")
ctx = context.WithValue(ctx, logger.UserIDKey, "user-67890")

// All subsequent logs will include context
logger.InfoContext(ctx, "User authenticated", 
    zap.String("method", "oauth2"),
)

// Output: {"level":"info","request_id":"req-12345","user_id":"user-67890","message":"User authenticated","method":"oauth2"}
```

### Security and Audit Logging

```go
// Security events
logger.SecurityEvent("Failed login attempt", 
    zap.String("ip", "192.168.1.100"),
    zap.Int("attempts", 3),
)

// Audit logging
logger.AuditLog("UPDATE", "user_profile",
    zap.String("admin_id", "admin-001"),
    zap.String("target_user", "user-123"),
)

// Sensitive data automatically redacted
logger.Info("User registration",
    zap.String("email", "user@example.com"),
    zap.String("password", "secret123"), // Automatically becomes [REDACTED]
)
```

### Error Handling

```go
// Create structured errors
notFoundErr := errs.NewNotFoundError("User not found")
validationErr := errs.NewValidationError("Invalid email format")

// Add context to errors
err := errs.NewUnexpectedError("Database error").
    WithRequestID("req-123").
    WithCause(originalError)

// Wrap external errors
dbErr := sql.ErrNoRows
wrappedErr := errs.WrapError(dbErr, errs.CodeNotFound, "User lookup failed")

// Use in HTTP handlers
func handleError(w http.ResponseWriter, err error) {
    if appErr, ok := errs.AsAppError(err); ok {
        publicErr := appErr.AsPublic() // Safe for client response
        w.WriteHeader(appErr.GetHTTPStatus())
        json.NewEncoder(w).Encode(publicErr)
        return
    }
    
    // Handle unexpected errors
    w.WriteHeader(http.StatusInternalServerError)
    json.NewEncoder(w).Encode(map[string]string{
        "error": "Internal server error",
    })
}
```

### HTTP Middleware Integration

```go
func LoggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Add request ID to context
        requestID := r.Header.Get("X-Request-ID")
        if requestID == "" {
            requestID = generateRequestID()
        }
        
        ctx := context.WithValue(r.Context(), logger.RequestIDKey, requestID)
        
        // Log request
        logger.InfoContext(ctx, "HTTP request started",
            zap.String("method", r.Method),
            zap.String("path", r.URL.Path),
            zap.String("remote_addr", r.RemoteAddr),
        )
        
        // Process request
        next.ServeHTTP(w, r.WithContext(ctx))
        
        // Log completion
        duration := time.Since(start)
        logger.InfoContext(ctx, "HTTP request completed",
            zap.Duration("duration", duration),
        )
    })
}
```

## Error Types

### Built-in Error Types

```go
// HTTP 404
errs.NewNotFoundError("Resource not found")

// HTTP 400
errs.NewValidationError("Invalid input")

// HTTP 401
errs.NewUnauthorizedError("Authentication required")

// HTTP 403
errs.NewForbiddenError("Access denied")

// HTTP 429
errs.NewRateLimitError("Rate limit exceeded")

// HTTP 408
errs.NewTimeoutError("Request timeout")

// HTTP 500
errs.NewUnexpectedError("Internal server error")
```

### Custom Error Codes

```go
const (
    CodeNotFound     ErrorCode = "NOT_FOUND"
    CodeValidation   ErrorCode = "VALIDATION_ERROR"
    CodeUnauthorized ErrorCode = "UNAUTHORIZED"
    CodeForbidden    ErrorCode = "FORBIDDEN"
    CodeRateLimit    ErrorCode = "RATE_LIMIT"
    CodeTimeout      ErrorCode = "TIMEOUT"
    CodeUnexpected   ErrorCode = "INTERNAL_ERROR"
)
```

## Output Examples

### Development Output (Console)
```
2025-06-20T10:30:45.123Z	INFO	main.go:25	User authenticated	{"service": "user-service", "version": "dev", "user_id": "123", "method": "oauth2"}
2025-06-20T10:30:45.124Z	ERROR	main.go:30	Database error	{"service": "user-service", "version": "dev", "error": "connection timeout"}
```

### Production Output (JSON)
```json
{"level":"info","timestamp":"2025-06-20T10:30:45.123Z","caller":"main.go:25","message":"User authenticated","service":"user-service","version":"1.0.0","user_id":"123","method":"oauth2"}
{"level":"error","timestamp":"2025-06-20T10:30:45.124Z","caller":"main.go:30","message":"Database error","service":"user-service","version":"1.0.0","error":"connection timeout"}
```

## Security Features

### Automatic Data Redaction

The library automatically redacts sensitive information:

- **Field Names**: `password`, `token`, `key`, `secret`, `auth`, `credential`, `api_key`
- **Log Messages**: Messages containing sensitive keywords are sanitized
- **Stack Traces**: Excluded from production logs for security

### Audit Trail

```go
// Creates structured audit logs
logger.AuditLog("CREATE", "user_account",
    zap.String("actor", "admin-123"),
    zap.String("target", "user-456"),
    zap.String("ip_address", "192.168.1.100"),
)
```

## Best Practices

### 1. Always Use Context

```go
// Good: Context-aware logging
logger.InfoContext(ctx, "Operation completed")

// Avoid: Missing context
logger.Info("Operation completed")
```

### 2. Structure Your Logs

```go
// Good: Structured fields
logger.Info("User login", 
    zap.String("user_id", userID),
    zap.Duration("response_time", duration),
    zap.Bool("success", true),
)

// Avoid: String interpolation
logger.Info(fmt.Sprintf("User %s logged in successfully in %v", userID, duration))
```

### 3. Handle Errors Properly

```go
// Good: Use typed errors
if err != nil {
    return errs.NewValidationError("Invalid user input").WithCause(err)
}

// Avoid: Generic errors
if err != nil {
    return fmt.Errorf("something went wrong: %w", err)
}
```

### 4. Separate Public and Internal Errors

```go
// Internal logging (detailed)
logger.Error("Database connection failed", 
    zap.String("connection_string", connStr),
    zap.Error(err),
)

// Client response (sanitized)
publicErr := appErr.AsPublic()
return c.JSON(appErr.GetHTTPStatus(), publicErr)
```

## Dependencies

- [go.uber.org/zap](https://github.com/uber-go/zap) - High-performance logging library
- Go 1.18+ (for generics support)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v1.0.0
- Initial release
- Structured logging with zap
- Security-focused error handling
- Context propagation
- Automatic sensitive data redaction
- Environment-aware configuration
- HTTP status code mapping
- Audit logging capabilities

## Support

- 📖 [Documentation](https://github.com/yourusername/your-logging-lib/wiki)
- 🐛 [Issues](https://github.com/yourusername/your-logging-lib/issues)
- 💬 [Discussions](https://github.com/yourusername/your-logging-lib/discussions)