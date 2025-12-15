"""Email whitelist management for Cloudflare authentication.

This module provides email whitelist validation with domain support,
enabling authorization of specific emails or entire domains (@company.com).
Supports both individual email addresses, admin privilege detection, and user tier management.

Key Features:
    - Individual email whitelisting
    - Domain pattern support (@company.com allows all @company.com emails)
    - User tiers (admin/full/limited) for feature access control
    - Premium model access control
    - Runtime whitelist management

Dependencies:
    - pydantic: For configuration validation
    - logging: For audit trails

Called by:
    - src.cloudflare_auth.middleware: For authorization checks
    - Application code: For access control decisions
"""

import logging
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, field_validator

_email_validator_available: bool
_validate_email_func = None
_email_not_valid_error = None
try:
    from email_validator import EmailNotValidError, validate_email

    _email_validator_available = True
    _validate_email_func = validate_email
    _email_not_valid_error = EmailNotValidError
except ImportError:
    _email_validator_available = False

# Expose as uppercase for backwards compatibility
EMAIL_VALIDATOR_AVAILABLE = _email_validator_available


logger = logging.getLogger(__name__)


class UserTier(str, Enum):
    """User access tiers for model and feature restrictions.

    Attributes:
        ADMIN: Full access plus administrative privileges
        FULL: Full access to all features and premium models
        LIMITED: Limited access to basic features only
    """

    ADMIN = "admin"
    FULL = "full"
    LIMITED = "limited"

    @classmethod
    def from_string(cls, value: str) -> "UserTier":
        """Create UserTier from string value.

        Args:
            value: String representation of tier

        Returns:
            UserTier enum value

        Raises:
            ValueError: If value is not a valid tier
        """
        value = value.lower().strip()
        for tier in cls:
            if tier.value == value:
                return tier
        msg = f"Invalid user tier: {value}"
        raise ValueError(msg)

    @property
    def can_access_premium_models(self) -> bool:
        """Check if tier allows access to premium models.

        Returns:
            True for ADMIN and FULL tiers, False for LIMITED
        """
        return self in (UserTier.ADMIN, UserTier.FULL)

    @property
    def has_admin_privileges(self) -> bool:
        """Check if tier has admin privileges.

        Returns:
            True only for ADMIN tier
        """
        return self == UserTier.ADMIN


@dataclass
class WhitelistEntry:
    """Represents a whitelist entry with metadata.

    Attributes:
        value: Email address or domain pattern (@domain.com)
        is_domain: Whether this is a domain pattern vs individual email
        added_at: ISO timestamp when entry was added
        description: Optional description of why this entry exists
    """

    value: str
    is_domain: bool
    added_at: str
    description: str | None = None


class EmailWhitelistConfig(BaseModel):
    """Configuration for email whitelist validation.

    This Pydantic model validates and normalizes whitelist configuration
    from environment variables or config files.

    Attributes:
        whitelist: List of allowed emails/domains
        admin_emails: List of emails with admin privileges
        full_users: List of emails with full tier access
        limited_users: List of emails with limited tier access
        case_sensitive: Whether email matching is case-sensitive
    """

    whitelist: list[str] = []
    admin_emails: list[str] = []
    full_users: list[str] = []
    limited_users: list[str] = []
    case_sensitive: bool = False

    @field_validator(
        "whitelist", "admin_emails", "full_users", "limited_users", mode="before"
    )
    @classmethod
    def normalize_emails(cls, v: str | list[str]) -> list[str]:
        """Normalize email addresses to lowercase unless case_sensitive.

        Args:
            v: String (comma-separated) or list of emails

        Returns:
            List of normalized email addresses
        """
        if isinstance(v, str):
            v = [email.strip() for email in v.split(",") if email.strip()]
        return [email.strip().lower() for email in v] if v else []


class EmailWhitelistValidator:
    """Email whitelist validator with domain support.

    Validates email addresses against a whitelist that can contain:
    - Individual email addresses: user@example.com
    - Domain patterns: @company.com (allows any email from that domain)
    - Admin privilege detection for specific admin emails
    - User tier assignment (admin/full/limited)

    Example:
        validator = EmailWhitelistValidator(
            whitelist=["user@example.com", "@company.com"],
            admin_emails=["admin@company.com"],
            full_users=["@company.com"],
            limited_users=["contractor@external.com"]
        )

        if validator.is_authorized("test@company.com"):
            tier = validator.get_user_tier("test@company.com")
            if tier.can_access_premium_models:
                # Allow premium access
                pass
    """

    def __init__(
        self,
        whitelist: list[str],
        admin_emails: list[str] | None = None,
        full_users: list[str] | None = None,
        limited_users: list[str] | None = None,
        case_sensitive: bool = False,
    ) -> None:
        """Initialize the email whitelist validator.

        Args:
            whitelist: List of allowed emails and domains
            admin_emails: List of emails with admin privileges
            full_users: List of emails with full tier access
            limited_users: List of emails with limited tier access
            case_sensitive: Whether email matching should be case-sensitive
        """
        self.case_sensitive = case_sensitive
        self.admin_emails = self._normalize_emails(admin_emails or [])
        self.full_users = self._normalize_emails(full_users or [])
        self.limited_users = self._normalize_emails(limited_users or [])

        # Separate individual emails from domain patterns
        self.individual_emails = set()
        self.domain_patterns = set()

        for entry in self._normalize_emails(whitelist):
            if entry.startswith("@"):
                self.domain_patterns.add(entry)
            else:
                self.individual_emails.add(entry)

        logger.info(
            "Initialized email whitelist: %d individual emails, %d domain patterns, "
            "%d admin emails, %d full users, %d limited users",
            len(self.individual_emails),
            len(self.domain_patterns),
            len(self.admin_emails),
            len(self.full_users),
            len(self.limited_users),
        )

    def _normalize_emails(self, emails: list[str]) -> list[str]:
        """Normalize email list based on case sensitivity setting.

        Args:
            emails: List of email addresses to normalize

        Returns:
            Normalized list of emails
        """
        if not emails:
            return []

        normalized = []
        for email_item in emails:
            email = email_item.strip()
            if email:
                normalized.append(email if self.case_sensitive else email.lower())

        return normalized

    def _normalize_email(self, email: str) -> str:
        """Normalize a single email address.

        Args:
            email: Email address to normalize

        Returns:
            Normalized email address
        """
        return email.strip() if self.case_sensitive else email.strip().lower()

    def is_authorized(self, email: str) -> bool:
        """Check if email is authorized via whitelist.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            email: Email address to validate

        Returns:
            True if email is authorized, False otherwise
        """
        if not email:
            return False

        normalized_email = self._normalize_email(email)

        # Check individual email whitelist using constant-time comparison
        for allowed_email in self.individual_emails:
            if secrets.compare_digest(normalized_email, allowed_email):
                logger.debug("Email %s authorized via individual whitelist", email)
                return True

        # Check domain patterns using constant-time comparison
        if "@" in normalized_email:
            domain = "@" + normalized_email.split("@")[1]
            for allowed_domain in self.domain_patterns:
                if secrets.compare_digest(domain, allowed_domain):
                    logger.debug(
                        "Email %s authorized via domain pattern %s", email, domain
                    )
                    return True

        logger.debug("Email %s not authorized", email)
        return False

    def is_admin(self, email: str) -> bool:
        """Check if email has admin privileges.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            email: Email address to check

        Returns:
            True if email is an admin, False otherwise
        """
        if not email:
            return False

        normalized_email = self._normalize_email(email)

        # Use constant-time comparison to prevent timing attacks
        for admin_email in self.admin_emails:
            if secrets.compare_digest(normalized_email, admin_email):
                logger.debug("Email %s has admin privileges", email)
                return True

        return False

    def get_user_role(self, email: str) -> str:
        """Get user role based on email.

        Args:
            email: Email address to check

        Returns:
            'admin', 'user', or 'unauthorized'
        """
        if not self.is_authorized(email):
            return "unauthorized"

        return "admin" if self.is_admin(email) else "user"

    def get_user_tier(self, email: str) -> UserTier:
        """Get user tier based on email.

        Checks in priority order: admin -> full -> limited
        First checks exact email matches, then domain patterns.

        Args:
            email: Email address to check

        Returns:
            UserTier enum value

        Raises:
            ValueError: If email is not authorized
        """
        if not email:
            msg = "Email cannot be empty"
            raise ValueError(msg)

        if not self.is_authorized(email):
            msg = f"Email {email} is not authorized"
            raise ValueError(msg)

        normalized_email = self._normalize_email(email)

        # Check tiers in priority order
        tier_lists = (self.admin_emails, self.full_users, self.limited_users)
        tier_types = (UserTier.ADMIN, UserTier.FULL, UserTier.LIMITED)

        # First check exact email matches
        for tier_list, tier_type in zip(tier_lists, tier_types, strict=False):
            if normalized_email in tier_list:
                logger.debug(
                    "Email %s has %s tier (exact match)", email, tier_type.value
                )
                return tier_type

        # Then check domain pattern matches
        if "@" in normalized_email:
            domain = "@" + normalized_email.split("@")[1]
            for tier_list, tier_type in zip(tier_lists, tier_types, strict=False):
                if domain in tier_list:
                    logger.debug(
                        "Email %s has %s tier (domain match: %s)",
                        email,
                        tier_type.value,
                        domain,
                    )
                    return tier_type

        # Default to limited tier for authorized users not explicitly assigned
        logger.debug("Email %s defaulted to limited tier", email)
        return UserTier.LIMITED

    def can_access_premium_models(self, email: str) -> bool:
        """Check if email can access premium models.

        Args:
            email: Email address to check

        Returns:
            True if user can access premium models, False otherwise
        """
        try:
            tier = self.get_user_tier(email)
            return tier.can_access_premium_models
        except ValueError:
            return False

    def has_admin_privileges(self, email: str) -> bool:
        """Check if email has admin privileges.

        Args:
            email: Email address to check

        Returns:
            True if user has admin privileges, False otherwise
        """
        try:
            tier = self.get_user_tier(email)
            return tier.has_admin_privileges
        except ValueError:
            return False

    def get_whitelist_stats(self) -> dict[str, Any]:
        """Get statistics about the current whitelist configuration.

        Returns:
            Dictionary with whitelist statistics
        """
        return {
            "individual_emails": len(self.individual_emails),
            "domain_patterns": len(self.domain_patterns),
            "admin_emails": len(self.admin_emails),
            "full_users": len(self.full_users),
            "limited_users": len(self.limited_users),
            "total_entries": len(self.individual_emails) + len(self.domain_patterns),
            "case_sensitive": self.case_sensitive,
            "domains": list(self.domain_patterns),
            "tier_distribution": {
                "admin": len(self.admin_emails),
                "full": len(self.full_users),
                "limited": len(self.limited_users),
            },
        }

    def _check_empty_whitelist(self) -> list[str]:
        """Check if whitelist is empty.

        Returns:
            List of warning messages if whitelist is empty, empty list otherwise.
        """
        if not self.individual_emails and not self.domain_patterns:
            return ["Whitelist is empty - no users will be authorized"]
        return []

    def _check_tier_authorization(self, emails: list[str], tier_name: str) -> list[str]:
        """Check if tier emails are authorized in whitelist.

        Args:
            emails: List of email addresses to check.
            tier_name: Name of the tier for warning messages.

        Returns:
            List of warning messages for unauthorized emails.
        """
        warnings = []
        for email in emails:
            if not self.is_authorized(email):
                warnings.append(f"{tier_name} email {email} is not in whitelist")
        return warnings

    def _check_tier_conflicts(self) -> list[str]:
        """Check for emails assigned to multiple tiers.

        Returns:
            List of warning messages for emails in multiple tiers.
        """
        warnings = []
        all_tier_emails = (
            set(self.admin_emails) | set(self.full_users) | set(self.limited_users)
        )

        tier_map = {
            "admin": set(self.admin_emails),
            "full": set(self.full_users),
            "limited": set(self.limited_users),
        }

        for email in all_tier_emails:
            tiers = [name for name, emails in tier_map.items() if email in emails]
            if len(tiers) > 1:
                warnings.append(
                    f"Email {email} is assigned to multiple tiers: {', '.join(tiers)}"
                )
        return warnings

    def _check_public_domains(self) -> list[str]:
        """Check for potentially insecure public email domains.

        Returns:
            List of warning messages if public domains are in whitelist.
        """
        public_domains = {"@gmail.com", "@outlook.com"}
        if self.domain_patterns & public_domains:
            return [
                "Public email domains (@gmail.com, @outlook.com) in whitelist may be insecure"
            ]
        return []

    def validate_whitelist_config(self) -> list[str]:
        """Validate the whitelist configuration and return any warnings.

        Returns:
            List of warning messages about the configuration
        """
        warnings = []
        warnings.extend(self._check_empty_whitelist())
        warnings.extend(self._check_tier_authorization(self.admin_emails, "Admin"))
        warnings.extend(self._check_tier_authorization(self.full_users, "Full user"))
        warnings.extend(
            self._check_tier_authorization(self.limited_users, "Limited user")
        )
        warnings.extend(self._check_tier_conflicts())
        warnings.extend(self._check_public_domains())
        return warnings


class WhitelistManager:
    """Manager for dynamic whitelist operations.

    Provides runtime management of whitelist entries. Note that changes
    are not persisted - for permanent changes, update configuration.

    Example:
        manager = WhitelistManager(validator)
        manager.add_email("newuser@company.com")
        status = manager.check_email("newuser@company.com")
    """

    def __init__(self, validator: EmailWhitelistValidator) -> None:
        """Initialize whitelist manager with a validator.

        Args:
            validator: EmailWhitelistValidator instance to manage
        """
        self.validator = validator

    def _validate_empty_input(self, email: str) -> None:
        """Validate that email input is not empty.

        Args:
            email: Email string to validate

        Raises:
            ValueError: If email is empty or whitespace only
        """
        if not email or not email.strip():
            msg = "Email cannot be empty"
            raise ValueError(msg)

    def _validate_email_with_library(self, email: str) -> str:
        """Validate email using email-validator library.

        Args:
            email: Email to validate

        Returns:
            Normalized email address

        Raises:
            RuntimeError: If email-validator is not available.
            ValueError: If email format is invalid.
        """
        if _validate_email_func is None:
            msg = "email-validator is not available"
            raise RuntimeError(msg)
        try:
            valid = _validate_email_func(email, check_deliverability=False)
            return valid.normalized if not self.validator.case_sensitive else email
        except _email_not_valid_error as e:  # type: ignore[misc]
            msg = f"Invalid email format: {e!s}"
            raise ValueError(msg) from e

    def _validate_email_basic(self, email: str) -> None:
        """Basic email validation without email-validator library.

        Args:
            email: Email to validate

        Raises:
            ValueError: If email format is invalid
        """
        if "@" not in email or email.count("@") != 1:
            msg = "Invalid email format: must contain exactly one @"
            raise ValueError(msg)

        local, domain = email.split("@")
        if not local or not domain or "." not in domain:
            msg = "Invalid email format"
            raise ValueError(msg)

    def _validate_email_format(self, email: str) -> str:
        """Validate individual email format.

        Delegates to library validation if available, otherwise uses basic validation.
        May raise ValueError from helper methods if email format is invalid.

        Args:
            email: Email address to validate

        Returns:
            Normalized email address
        """
        if _email_validator_available and _validate_email_func is not None:
            return self._validate_email_with_library(email)
        self._validate_email_basic(email)
        return email

    def _validate_domain_pattern(self, pattern: str) -> None:
        """Validate domain pattern format.

        Args:
            pattern: Domain pattern to validate (e.g., @domain.tld)

        Raises:
            ValueError: If domain pattern is invalid
        """
        if pattern.count("@") != 1:
            msg = "Invalid domain pattern: must be @domain.tld"
            raise ValueError(msg)

        domain_part = pattern[1:]  # Remove @
        if not domain_part or "." not in domain_part:
            msg = "Invalid domain pattern: must include valid domain"
            raise ValueError(msg)

    def _add_to_collections(
        self, normalized_email: str, is_admin: bool, original_email: str
    ) -> None:
        """Add email to appropriate whitelist collections.

        Args:
            normalized_email: Normalized email or domain pattern
            is_admin: Whether to add to admin list
            original_email: Original email for logging
        """
        if normalized_email.startswith("@"):
            self.validator.domain_patterns.add(normalized_email)
        else:
            self.validator.individual_emails.add(normalized_email)

        if is_admin:
            self.validator.admin_emails.append(normalized_email)

        logger.info("Added email %s to whitelist (admin: %s)", original_email, is_admin)

    def add_email(self, email: str, is_admin: bool = False) -> bool:
        """Add email to whitelist (runtime operation).

        Note: This is for runtime operations. For persistent changes,
        update the configuration file directly.

        Args:
            email: Email or domain pattern to add
            is_admin: Whether email should have admin privileges

        Returns:
            True if email was added successfully

        Raises:
            ValueError: If email format is invalid
        """
        try:
            self._validate_empty_input(email)
            normalized_email = self.validator._normalize_email(email)

            if normalized_email.startswith("@"):
                self._validate_domain_pattern(normalized_email)
            else:
                normalized_email = self._validate_email_format(normalized_email)

            self._add_to_collections(normalized_email, is_admin, email)
            return True

        except ValueError:
            raise
        except Exception as e:
            logger.exception("Failed to add email %s to whitelist: %s", email, e)
            msg = f"Failed to add email: {e!s}"
            raise ValueError(msg) from e

    def remove_email(self, email: str) -> bool:
        """Remove email from whitelist (runtime operation).

        Args:
            email: Email or domain pattern to remove

        Returns:
            True if email was removed successfully
        """
        try:
            normalized_email = self.validator._normalize_email(email)

            # Remove from individual emails or domain patterns
            removed = False
            if normalized_email in self.validator.individual_emails:
                self.validator.individual_emails.remove(normalized_email)
                removed = True

            if normalized_email in self.validator.domain_patterns:
                self.validator.domain_patterns.remove(normalized_email)
                removed = True

            # Remove from admin emails if present
            if normalized_email in self.validator.admin_emails:
                self.validator.admin_emails.remove(normalized_email)

            if removed:
                logger.info("Removed email %s from whitelist", email)
            else:
                logger.warning("Email %s not found in whitelist", email)

            return removed

        except Exception as e:
            logger.exception("Failed to remove email %s from whitelist: %s", email, e)
            return False

    def check_email(self, email: str) -> dict[str, Any]:
        """Check email status and provide detailed information.

        Args:
            email: Email to check

        Returns:
            Dictionary with email status information
        """
        return {
            "email": email,
            "is_authorized": self.validator.is_authorized(email),
            "is_admin": self.validator.is_admin(email),
            "role": self.validator.get_user_role(email),
            "normalized_email": self.validator._normalize_email(email),
        }


def create_validator_from_env(
    whitelist_str: str,
    admin_emails_str: str = "",
    full_users_str: str = "",
    limited_users_str: str = "",
) -> EmailWhitelistValidator:
    """Create EmailWhitelistValidator from environment variable strings.

    This is a convenience function for creating validators from
    comma-separated environment variable values.

    Args:
        whitelist_str: Comma-separated string of emails/domains
        admin_emails_str: Comma-separated string of admin emails
        full_users_str: Comma-separated string of full tier users
        limited_users_str: Comma-separated string of limited tier users

    Returns:
        Configured EmailWhitelistValidator

    Example:
        validator = create_validator_from_env(
            whitelist_str="user@example.com,@company.com",
            admin_emails_str="admin@company.com",
            full_users_str="@company.com"
        )
    """
    whitelist = (
        [email.strip() for email in whitelist_str.split(",") if email.strip()]
        if whitelist_str
        else []
    )
    admin_emails = (
        [email.strip() for email in admin_emails_str.split(",") if email.strip()]
        if admin_emails_str
        else []
    )
    full_users = (
        [email.strip() for email in full_users_str.split(",") if email.strip()]
        if full_users_str
        else []
    )
    limited_users = (
        [email.strip() for email in limited_users_str.split(",") if email.strip()]
        if limited_users_str
        else []
    )

    return EmailWhitelistValidator(
        whitelist=whitelist,
        admin_emails=admin_emails,
        full_users=full_users,
        limited_users=limited_users,
    )
