"""Custom exceptions for GCS utilities."""


class GCSError(Exception):
    """Base exception for GCS utilities."""


class GCSAuthError(GCSError):
    """Raised when authentication to GCS fails."""


class GCSUploadError(GCSError):
    """Raised when file upload to GCS fails."""


class GCSDownloadError(GCSError):
    """Raised when file download from GCS fails."""


class GCSNotFoundError(GCSError):
    """Raised when a requested GCS object is not found."""


class GCSConfigError(GCSError):
    """Raised when GCS configuration is invalid or missing."""
