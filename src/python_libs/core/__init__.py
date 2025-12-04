"""Core configuration, settings, and exception modules."""

from python_libs.core.config import Settings
from python_libs.core.exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    BusinessLogicError,
    ConfigurationError,
    DatabaseError,
    ExternalServiceError,
    ProjectBaseError,
    ResourceNotFoundError,
    ValidationError,
)

__all__ = [
    # Exceptions (sorted alphabetically)
    "APIError",
    "AuthenticationError",
    "AuthorizationError",
    "BusinessLogicError",
    "ConfigurationError",
    "DatabaseError",
    "ExternalServiceError",
    "ProjectBaseError",
    "ResourceNotFoundError",
    # Configuration
    "Settings",
    "ValidationError",
]
