"""Cloudflare API exceptions.

Custom exceptions for Cloudflare API operations with detailed error context.
"""

from typing import Any


class CloudflareAPIError(Exception):
    """Base exception for Cloudflare API errors.

    Attributes:
        message: Error message
        code: Cloudflare error code (if available)
        errors: List of error details from Cloudflare response
        response: Raw response data (if available)
    """

    def __init__(
        self,
        message: str,
        code: int | None = None,
        errors: list[dict[str, Any]] | None = None,
        response: dict[str, Any] | None = None,
    ) -> None:
        """Initialize CloudflareAPIError.

        Args:
            message: Error message
            code: Cloudflare error code
            errors: List of error details
            response: Raw response data
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.errors = errors or []
        self.response = response

    def __str__(self) -> str:
        """Return string representation."""
        parts = [self.message]
        if self.code:
            parts.append(f"(code: {self.code})")
        if self.errors:
            error_msgs = [e.get("message", str(e)) for e in self.errors]
            parts.append(f"Details: {'; '.join(error_msgs)}")
        return " ".join(parts)


class CloudflareAuthError(CloudflareAPIError):
    """Authentication or authorization error.

    Raised when API token is invalid, expired, or lacks required permissions.
    """



class CloudflareRateLimitError(CloudflareAPIError):
    """Rate limit exceeded error.

    Raised when too many requests are made in a short period.

    Attributes:
        retry_after: Seconds to wait before retrying (if provided)
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize rate limit error.

        Args:
            message: Error message
            retry_after: Seconds to wait before retrying
            **kwargs: Additional arguments for base class
        """
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class CloudflareNotFoundError(CloudflareAPIError):
    """Resource not found error.

    Raised when a requested resource (list, item, zone) doesn't exist.

    Attributes:
        resource_type: Type of resource not found
        resource_id: ID of the missing resource
    """

    def __init__(
        self,
        message: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize not found error.

        Args:
            message: Error message
            resource_type: Type of resource (e.g., "list", "item")
            resource_id: ID of the missing resource
            **kwargs: Additional arguments for base class
        """
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.resource_id = resource_id


class CloudflareValidationError(CloudflareAPIError):
    """Validation error for invalid request data.

    Raised when request parameters fail Cloudflare's validation.

    Attributes:
        field: Field that failed validation (if known)
    """

    def __init__(
        self,
        message: str,
        field: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize validation error.

        Args:
            message: Error message
            field: Field that failed validation
            **kwargs: Additional arguments for base class
        """
        super().__init__(message, **kwargs)
        self.field = field


class CloudflareBulkOperationError(CloudflareAPIError):
    """Bulk operation error.

    Raised when a bulk operation fails or times out.

    Attributes:
        operation_id: ID of the failed operation
        status: Final status of the operation
    """

    def __init__(
        self,
        message: str,
        operation_id: str | None = None,
        status: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize bulk operation error.

        Args:
            message: Error message
            operation_id: ID of the failed operation
            status: Final status of the operation
            **kwargs: Additional arguments for base class
        """
        super().__init__(message, **kwargs)
        self.operation_id = operation_id
        self.status = status


class CloudflareConflictError(CloudflareAPIError):
    """Conflict error.

    Raised when an operation conflicts with existing state,
    e.g., creating a list with a name that already exists,
    or when another bulk operation is in progress.
    """

