package errs

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// ErrorCode represents custom error codes for better categorization
type ErrorCode string

const (
	CodeNotFound     ErrorCode = "NOT_FOUND"
	CodeUnexpected   ErrorCode = "INTERNAL_ERROR"
	CodeValidation   ErrorCode = "VALIDATION_ERROR"
	CodeUnauthorized ErrorCode = "UNAUTHORIZED"
	CodeForbidden    ErrorCode = "FORBIDDEN"
	CodeRateLimit    ErrorCode = "RATE_LIMIT"
	CodeTimeout      ErrorCode = "TIMEOUT"
)

// AppError represents application-specific errors with enhanced security and debugging info
type AppError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	HTTPCode  int       `json:"-"` // Don't expose HTTP codes in JSON
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id,omitempty"`

	// Internal fields - not exposed in JSON
	InternalMessage string `json:"-"` // Technical details for logs
	StackTrace      string `json:"-"` // Stack trace for debugging
	Cause           error  `json:"-"` // Original error for wrapping
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.InternalMessage != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.InternalMessage)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap implements error unwrapping for Go 1.13+
func (e *AppError) Unwrap() error {
	return e.Cause
}

// WithRequestID adds request ID for request tracing
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithCause wraps another error
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	if e.InternalMessage == "" && cause != nil {
		e.InternalMessage = cause.Error()
	}
	return e
}

// AsPublic returns a sanitized version safe for client responses
func (e *AppError) AsPublic() *AppError {
	return &AppError{
		Code:      e.Code,
		Message:   e.Message,
		HTTPCode:  e.HTTPCode,
		Timestamp: e.Timestamp,
		RequestID: e.RequestID,
		// Internal fields are omitted
	}
}

// GetHTTPStatus returns the appropriate HTTP status code
func (e *AppError) GetHTTPStatus() int {
	if e.HTTPCode != 0 {
		return e.HTTPCode
	}
	// Fallback mapping
	switch e.Code {
	case CodeNotFound:
		return http.StatusNotFound
	case CodeValidation:
		return http.StatusBadRequest
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden:
		return http.StatusForbidden
	case CodeRateLimit:
		return http.StatusTooManyRequests
	case CodeTimeout:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}

// newAppError creates a new AppError with stack trace
func newAppError(code ErrorCode, message string, httpCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    sanitizeMessage(message),
		HTTPCode:   httpCode,
		Timestamp:  time.Now().UTC(),
		StackTrace: captureStackTrace(),
	}
}

// sanitizeMessage removes potential sensitive information from error messages
func sanitizeMessage(message string) string {
	// Remove common sensitive patterns
	sensitive := []string{
		"password", "token", "key", "secret", "auth",
		"sql:", "database", "connection", "credential",
	}

	lower := strings.ToLower(message)
	for _, pattern := range sensitive {
		if strings.Contains(lower, pattern) {
			return "An error occurred. Please contact support."
		}
	}

	// Limit message length to prevent information disclosure
	if len(message) > 200 {
		return message[:200] + "..."
	}

	return message
}

// captureStackTrace captures the current stack trace
func captureStackTrace() string {
	const maxStackSize = 50
	stack := make([]uintptr, maxStackSize)
	length := runtime.Callers(3, stack) // Skip 3 frames to get to actual caller

	var frames []string
	for i := 0; i < length; i++ {
		pc := stack[i]
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}
		file, line := fn.FileLine(pc)
		frames = append(frames, fmt.Sprintf("%s:%d %s", file, line, fn.Name()))
	}

	return strings.Join(frames, "\n")
}

// Constructor functions with improved validation

func NewNotFoundError(message string) *AppError {
	if message == "" {
		message = "Resource not found"
	}
	return newAppError(CodeNotFound, message, http.StatusNotFound)
}

func NewUnexpectedError(message string) *AppError {
	if message == "" {
		message = "An unexpected error occurred"
	}
	return newAppError(CodeUnexpected, message, http.StatusInternalServerError)
}

func NewValidationError(message string) *AppError {
	if message == "" {
		message = "Validation failed"
	}
	return newAppError(CodeValidation, message, http.StatusBadRequest)
}

func NewUnauthorizedError(message string) *AppError {
	if message == "" {
		message = "Authentication required"
	}
	return newAppError(CodeUnauthorized, message, http.StatusUnauthorized)
}

func NewForbiddenError(message string) *AppError {
	if message == "" {
		message = "Access denied"
	}
	return newAppError(CodeForbidden, message, http.StatusForbidden)
}

func NewRateLimitError(message string) *AppError {
	if message == "" {
		message = "Rate limit exceeded"
	}
	return newAppError(CodeRateLimit, message, http.StatusTooManyRequests)
}

func NewTimeoutError(message string) *AppError {
	if message == "" {
		message = "Request timeout"
	}
	return newAppError(CodeTimeout, message, http.StatusRequestTimeout)
}

// Utility functions for error handling

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	var appError *AppError
	ok := errors.As(err, &appError)
	return ok
}

// AsAppError attempts to convert an error to AppError
func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// WrapError wraps a generic error as an AppError
func WrapError(err error, code ErrorCode, message string) *AppError {
	if err == nil {
		return nil
	}

	appErr := newAppError(code, message, http.StatusInternalServerError)
	return appErr.WithCause(err)
}
