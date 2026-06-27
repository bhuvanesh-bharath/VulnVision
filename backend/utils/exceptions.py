"""
VulnVision Custom Exception Hierarchy.
Centralized exception definitions for consistent error handling across the platform.
"""


class VulnVisionError(Exception):
    """Base exception for all VulnVision errors."""

    def __init__(self, message='An unexpected error occurred', status_code=500, details=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}

    def to_dict(self):
        """Serialize exception to dictionary for API responses."""
        return {
            'error': True,
            'message': self.message,
            'status_code': self.status_code,
            'details': self.details
        }


class ValidationError(VulnVisionError):
    """Raised when input validation fails."""

    def __init__(self, message='Validation failed', details=None):
        super().__init__(message=message, status_code=400, details=details)


class NotFoundError(VulnVisionError):
    """Raised when a requested resource is not found."""

    def __init__(self, resource_type='Resource', resource_id=None):
        message = f'{resource_type} not found'
        if resource_id:
            message = f'{resource_type} with ID {resource_id} not found'
        super().__init__(message=message, status_code=404)


class ScanError(VulnVisionError):
    """Raised when a scan operation fails."""

    def __init__(self, message='Scan operation failed', details=None):
        super().__init__(message=message, status_code=500, details=details)


class ScanTimeoutError(ScanError):
    """Raised when a scan exceeds its timeout limit."""

    def __init__(self, target=None, timeout=None):
        message = 'Scan timed out'
        details = {}
        if target:
            details['target'] = target
        if timeout:
            details['timeout_seconds'] = timeout
            message = f'Scan timed out after {timeout} seconds'
        super().__init__(message=message, details=details)


class NetworkError(VulnVisionError):
    """Raised when a network operation fails."""

    def __init__(self, message='Network operation failed', details=None):
        super().__init__(message=message, status_code=503, details=details)


class DatabaseError(VulnVisionError):
    """Raised when a database operation fails."""

    def __init__(self, message='Database operation failed', details=None):
        super().__init__(message=message, status_code=500, details=details)


class ReportGenerationError(VulnVisionError):
    """Raised when report generation fails."""

    def __init__(self, message='Report generation failed', report_type=None):
        details = {}
        if report_type:
            details['report_type'] = report_type
        super().__init__(message=message, status_code=500, details=details)


class ConfigurationError(VulnVisionError):
    """Raised when application configuration is invalid."""

    def __init__(self, message='Configuration error', details=None):
        super().__init__(message=message, status_code=500, details=details)


class AuthenticationError(VulnVisionError):
    """Raised when authentication fails."""

    def __init__(self, message='Authentication required'):
        super().__init__(message=message, status_code=401)


class PermissionError(VulnVisionError):
    """Raised when user lacks required permissions."""

    def __init__(self, message='Insufficient permissions'):
        super().__init__(message=message, status_code=403)


class DuplicateError(VulnVisionError):
    """Raised when a duplicate resource is detected."""

    def __init__(self, resource_type='Resource', identifier=None):
        message = f'{resource_type} already exists'
        if identifier:
            message = f'{resource_type} with identifier {identifier} already exists'
        super().__init__(message=message, status_code=409)


class RateLimitError(VulnVisionError):
    """Raised when rate limit is exceeded."""

    def __init__(self, message='Rate limit exceeded', retry_after=None):
        details = {}
        if retry_after:
            details['retry_after_seconds'] = retry_after
        super().__init__(message=message, status_code=429, details=details)
