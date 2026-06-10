"""Cloudflare API exceptions.

Custom exceptions for Cloudflare API operations with detailed error context.
"""

from typing import Any


class CloudflareAPIError(Exception):
    """Base exception for Cloudflare API errors.

    Args:
        message (str): Error message
        code (int | None): Cloudflare error code (if available)
        errors (list[dict[str, Any]] | None): List of error details from
            Cloudflare response
        response (dict[str, Any] | None): Raw response data (if available)
    """

    def __init__(
        self,
        message: str,
        code: int | None = None,
        errors: list[dict[str, Any]] | None = None,
        response: dict[str, Any] | None = None,
    ) -> None:
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

    Args:
        message (str): Error message
        retry_after (int | None): Seconds to wait before retrying
        **kwargs (Any): Additional arguments for base class
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class CloudflareNotFoundError(CloudflareAPIError):
    """Resource not found error.

    Raised when a requested resource (list, item, zone) doesn't exist.

    Args:
        message (str): Error message
        resource_type (str | None): Type of resource (e.g., "list", "item")
        resource_id (str | None): ID of the missing resource
        **kwargs (Any): Additional arguments for base class
    """

    def __init__(
        self,
        message: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.resource_id = resource_id


class CloudflareValidationError(CloudflareAPIError):
    """Validation error for invalid request data.

    Raised when request parameters fail Cloudflare's validation.

    Args:
        message (str): Error message
        field (str | None): Field that failed validation
        **kwargs (Any): Additional arguments for base class
    """

    def __init__(
        self,
        message: str,
        field: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.field = field


class CloudflareBulkOperationError(CloudflareAPIError):
    """Bulk operation error.

    Raised when a bulk operation fails or times out.

    Args:
        message (str): Error message
        operation_id (str | None): ID of the failed operation
        status (str | None): Final status of the operation
        **kwargs (Any): Additional arguments for base class
    """

    def __init__(
        self,
        message: str,
        operation_id: str | None = None,
        status: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.operation_id = operation_id
        self.status = status


class CloudflareConflictError(CloudflareAPIError):
    """Conflict error.

    Raised when an operation conflicts with existing state,
    e.g., creating a list with a name that already exists,
    or when another bulk operation is in progress.
    """
