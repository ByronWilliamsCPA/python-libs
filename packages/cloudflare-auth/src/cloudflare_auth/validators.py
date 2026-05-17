"""JWT validation utilities for Cloudflare Access tokens.

This module provides comprehensive JWT token validation using Cloudflare's
public certificates. It implements proper cryptographic verification,
claim validation, and certificate caching.

Key Components:
    - CloudflareJWTValidator: Main validator class
    - Certificate caching for performance
    - Audience and issuer validation
    - Expiration checking

Architecture:
    The validator fetches Cloudflare's public certificates and caches them
    for efficient token validation. It verifies the JWT signature using
    RS256 algorithm and validates all required claims.

Dependencies:
    - PyJWT: For JWT encoding/decoding
    - cryptography: For RSA key handling
    - httpx: For async certificate fetching
    - src.config.settings: For Cloudflare configuration

Called by:
    - src.cloudflare_auth.middleware: During request authentication
    - Application security layer: For token validation

Complexity: O(1) for cached certificates, O(n) for initial fetch
"""

import logging
from datetime import datetime, timezone
from typing import Any

import jwt
from jwt import PyJWKClient

from cloudflare_auth.config import CloudflareSettings, get_cloudflare_settings
from cloudflare_auth.models import CloudflareJWTClaims

logger = logging.getLogger(__name__)

# Allowlist of safe asymmetric JWT algorithms. Cloudflare Access signs with
# RS256; symmetric algorithms (HS*) and "none" are rejected to prevent
# algorithm-confusion and signature-stripping attacks where an attacker
# crafts a token using the public key (treated as HMAC secret) or no signature.
_ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
)

# Maximum tolerated clock skew between issuer and verifier (seconds).
_JWT_LEEWAY_SECONDS: int = 30


class CloudflareJWTValidator:
    """Validates JWT tokens from Cloudflare Access.

    This class handles all aspects of JWT validation including:
    - Signature verification using Cloudflare's public keys
    - Audience and issuer validation
    - Expiration checking
    - Claim extraction and validation

    Attributes:
        settings: Cloudflare configuration settings
        jwks_client: Client for fetching JWT signing keys
        _last_key_refresh: Timestamp of last key refresh

    Example:
        validator = CloudflareJWTValidator()
        try:
            claims = validator.validate_token(jwt_token)
            print(f"Authenticated: {claims.email}")
        except ValueError as e:
            print(f"Authentication failed: {e}")
    """

    def __init__(self, settings: CloudflareSettings | None = None) -> None:
        """Initialize JWT validator.

        Args:
            settings: Optional CloudflareSettings instance (uses default if not provided)

        Raises:
            ValueError: If configured ``jwt_algorithm`` is not in the
                allowlist of safe asymmetric algorithms.
        """
        self.settings = settings or get_cloudflare_settings()

        # #CRITICAL: Security: reject unsafe algorithms at construction time.
        # If misconfigured to "none" or an HS* algorithm, an attacker could
        # forge tokens or bypass signature verification entirely.
        if self.settings.jwt_algorithm not in _ALLOWED_JWT_ALGORITHMS:
            msg = (
                f"Unsupported JWT algorithm: {self.settings.jwt_algorithm!r}. "
                f"Allowed algorithms: {sorted(_ALLOWED_JWT_ALGORITHMS)}"
            )
            raise ValueError(msg)

        if not self.settings.cloudflare_team_domain:
            logger.warning(
                "Cloudflare team domain not configured. JWT validation will fail."
            )

        # Initialize JWKS client for fetching public keys
        if self.settings.certs_url:
            self.jwks_client = PyJWKClient(
                self.settings.certs_url,
                cache_keys=True,
                max_cached_keys=self.settings.jwt_cache_max_keys,
            )
        else:
            self.jwks_client = None

        self._last_key_refresh: datetime | None = None

    def validate_token(  # noqa: C901  -- per-PyJWT-exception handlers are flat and clearer than nesting
        self,
        token: str,
    ) -> CloudflareJWTClaims:
        """Validate a Cloudflare Access JWT token.

        This method performs comprehensive validation:
        1. Signature verification using Cloudflare's public keys
        2. Algorithm enforcement (asymmetric only, allowlist)
        3. Expiration (``exp``) and not-before (``nbf``) checking
        4. Issued-at (``iat``) sanity checking
        5. Issuer validation
        6. Audience validation
        7. Required claims presence

        Signature verification, expiration, and required-claim checks
        cannot be disabled by callers.

        Args:
            token: JWT token string from Cf-Access-Jwt-Assertion header

        Returns:
            CloudflareJWTClaims object with validated claims

        Raises:
            ValueError: If token is invalid, expired, or claims are missing
            RuntimeError: If validator is not properly configured

        Time Complexity: O(1) with cached keys, O(n) on cache miss
        Space Complexity: O(1) for token validation

        Called by:
            - CloudflareAuthMiddleware.authenticate_request()
            - Manual token validation in endpoints

        Example:
            validator = CloudflareJWTValidator()
            try:
                claims = validator.validate_token(token)
                if claims.email == "admin@example.com":
                    # Grant admin access
                    pass
            except ValueError as e:
                # Handle authentication failure
                logger.error(f"Auth failed: {e}")
        """
        if not self.jwks_client:
            msg = "JWT validator not configured. Set CLOUDFLARE_TEAM_DOMAIN."
            raise RuntimeError(msg)

        try:
            # Get the signing key from the JWT header
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and validate the token. All security-relevant options
            # are explicit so future PyJWT default changes cannot silently
            # weaken validation. The ``algorithms`` argument is fixed to
            # the constructor-validated value, so PyJWT will reject any
            # token whose header advertises an algorithm outside the
            # asymmetric allowlist.
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=[self.settings.jwt_algorithm],
                audience=self.settings.cloudflare_audience_tag,
                issuer=self.settings.issuer,
                leeway=_JWT_LEEWAY_SECONDS,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": bool(self.settings.cloudflare_audience_tag),
                    "verify_iss": bool(self.settings.issuer),
                    "require": ["exp", "iat", "iss", "sub", "aud"],
                },
            )

            # Validate required claims (defence-in-depth on top of "require")
            self._validate_required_claims(payload)

            # Create and return claims object
            claims = CloudflareJWTClaims(**payload)

            # Additional validation
            if self.settings.require_email_verification and not claims.email:
                msg = "Email claim is required but missing"
                raise ValueError(msg)

            # Check email domain if restrictions are configured
            if not self.settings.is_email_allowed(claims.email):
                msg = f"Email domain not allowed: {claims.email}"
                raise ValueError(msg)

            logger.debug(
                "Successfully validated JWT for user: %s",
                claims.email,
            )

            return claims

        except jwt.ExpiredSignatureError as e:
            logger.warning("JWT token expired: %s", str(e))
            msg = "Token has expired"
            raise ValueError(msg) from e

        except jwt.ImmatureSignatureError as e:
            logger.warning("JWT token not yet valid: %s", str(e))
            msg = "Token is not yet valid (nbf)"
            raise ValueError(msg) from e

        except jwt.MissingRequiredClaimError as e:
            logger.warning("JWT missing required claim: %s", str(e))
            msg = f"Missing required claim: {e!s}"
            raise ValueError(msg) from e

        except jwt.InvalidAudienceError as e:
            logger.warning("Invalid JWT audience: %s", str(e))
            msg = "Invalid token audience"
            raise ValueError(msg) from e

        except jwt.InvalidIssuerError as e:
            logger.warning("Invalid JWT issuer: %s", str(e))
            msg = "Invalid token issuer"
            raise ValueError(msg) from e

        except jwt.InvalidAlgorithmError as e:
            logger.warning("Invalid JWT algorithm: %s", str(e))
            msg = "Invalid token algorithm"
            raise ValueError(msg) from e

        except jwt.InvalidSignatureError as e:
            logger.warning("Invalid JWT signature: %s", str(e))
            msg = "Invalid token signature"
            raise ValueError(msg) from e

        except jwt.DecodeError as e:
            logger.warning("Failed to decode JWT: %s", str(e))
            msg = "Invalid token format"
            raise ValueError(msg) from e

        except jwt.InvalidTokenError as e:
            # Catch-all for any other PyJWT validation failure rather than
            # a blanket ``except Exception`` (which would mask programmer
            # errors and ruff BLE001).
            logger.warning("JWT validation failed: %s", str(e))
            msg = "Token validation failed"
            raise ValueError(msg) from e

    def _validate_required_claims(self, payload: dict[str, Any]) -> None:
        """Validate that required claims are present.

        Args:
            payload: Decoded JWT payload

        Raises:
            ValueError: If required claims are missing
        """
        required_claims = ["email", "iss", "aud", "sub", "iat", "exp"]

        missing_claims = [claim for claim in required_claims if claim not in payload]

        if missing_claims:
            msg = f"Missing required JWT claims: {', '.join(missing_claims)}"
            raise ValueError(msg)

    async def validate_token_async(
        self,
        token: str,
    ) -> CloudflareJWTClaims:
        """Async version of validate_token.

        This method provides the same validation as validate_token but
        can be used in async contexts. Note that JWT validation itself
        is CPU-bound and not truly async.

        Args:
            token: JWT token string

        Returns:
            CloudflareJWTClaims object with validated claims

        Raises:
            ValueError: If token is invalid
        """
        # JWT validation is CPU-bound, not I/O bound
        # But we provide async interface for consistency
        return self.validate_token(token)

    def refresh_keys(self) -> None:
        """Force refresh of cached public keys.

        This method can be called to manually refresh the cached
        Cloudflare public keys. Useful for handling key rotation.

        Note:
            PyJWKClient handles key caching automatically. Creating a new
            instance will fetch fresh keys on next validation.
        """
        if self.jwks_client and self.settings.certs_url:
            # Create a new JWKS client to force key refresh
            # This is safer than accessing private attributes
            self.jwks_client = PyJWKClient(
                self.settings.certs_url,
                cache_keys=True,
                max_cached_keys=self.settings.jwt_cache_max_keys,
            )
            self._last_key_refresh = datetime.now(tz=timezone.utc)
            logger.info("Cloudflare public keys client refreshed")

    @property
    def is_configured(self) -> bool:
        """Check if validator is properly configured.

        Returns:
            True if validator has necessary configuration
        """
        return bool(
            self.settings.cloudflare_team_domain
            and self.settings.cloudflare_audience_tag
            and self.jwks_client
        )

    def get_unverified_claims(self, token: str) -> dict[str, Any]:
        """Get claims from token without verification. DEBUG USE ONLY.

        WARNING: This method does NOT verify the token signature,
        expiration, issuer, audience, or any other claim. The returned
        data MUST NOT be used for authentication, authorization, or any
        security-relevant decision. Use ``validate_token`` instead.

        A warning is logged on every call so misuse is visible in
        production logs.

        Args:
            token: JWT token string

        Returns:
            Dictionary of unverified claims, or empty dict on parse error.
        """
        logger.warning(
            "get_unverified_claims() called - claims are NOT verified and "
            "MUST NOT be trusted for any security decision."
        )
        try:
            return jwt.decode(
                token,
                options={"verify_signature": False},
            )
        except jwt.InvalidTokenError as e:
            logger.warning("Failed to decode unverified token: %s", str(e))
            return {}
