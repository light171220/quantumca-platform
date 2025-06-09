package utils

import (
	"fmt"
	"net/http"
)

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API Error %d: %s", e.Code, e.Message)
}

func NewAPIError(code int, message string, details ...string) *APIError {
	err := &APIError{
		Code:    code,
		Message: message,
	}
	if len(details) > 0 {
		err.Details = details[0]
	}
	return err
}

func BadRequestError(message string, details ...string) *APIError {
	return NewAPIError(http.StatusBadRequest, message, details...)
}

func UnauthorizedError(message string, details ...string) *APIError {
	return NewAPIError(http.StatusUnauthorized, message, details...)
}

func ForbiddenError(message string, details ...string) *APIError {
	return NewAPIError(http.StatusForbidden, message, details...)
}

func NotFoundError(message string, details ...string) *APIError {
	return NewAPIError(http.StatusNotFound, message, details...)
}

func ConflictError(message string, details ...string) *APIError {
	return NewAPIError(http.StatusConflict, message, details...)
}

func InternalServerError(message string, details ...string) *APIError {
	return NewAPIError(http.StatusInternalServerError, message, details...)
}

func ValidationError(field, message string) *APIError {
	return BadRequestError(fmt.Sprintf("Validation failed for field '%s'", field), message)
}