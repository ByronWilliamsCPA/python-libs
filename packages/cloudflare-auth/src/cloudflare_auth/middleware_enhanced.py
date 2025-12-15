"""Enhanced Cloudflare Access authentication middleware with JWT, whitelist, and sessions.

This module provides comprehensive FastAPI middleware that combines:
- JWT token validation for security
- Email whitelist with domain and tier support
- Session management with cookies
- Development mode for local testing

Key Features:
    - Secure JWT validation using Cloudflare certificates
    - Email whitelist with @domain.com pattern support
    - User tiers (admin/full/limited) for access control
    - In-memory session management with cookies
    - Development mode with mock users
    - Comprehensive logging and error handling

Dependencies:
    - fastapi: For Request/Response handling
    - starlette: For middleware base classes
    - src.cloudflare_auth.validators: For JWT validation
    - src.cloudflare_auth.whitelist: For email validation
    - src.cloudflare_auth.sessions: For session management

Called by:
    - FastAPI middleware stack during request processing

Example:
    from fastapi import FastAPI
    from cloudflare_auth import setup_cloudflare_auth_enhanced

    app = FastAPI()
    setup_cloudflare_auth_enhanced(
        app,
        whitelist=["user@example.com", "@company.com"],
        admin_emails=["admin@company.com"]
    )
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from cloudflare_auth.config import CloudflareSettings, get_cloudflare_settings
from cloudflare_auth.csrf import CSRFProtection
from cloudflare_auth.models import CloudflareUser
from cloudflare_auth.rate_limiter import InMemoryRateLimiter
from cloudflare_auth.sessions import SimpleSessionManager
from cloudflare_auth.utils import (
    get_client_ip,
    sanitize_email,
    sanitize_ip,
    sanitize_path,
)
from cloudflare_auth.validators import CloudflareJWTValidator
from cloudflare_auth.whitelist import EmailWhitelistValidator, UserTier

logger = logging.getLogger(__name__)


class CloudflareAuthMiddlewareEnhanced(BaseHTTPMiddleware):
    """Enhanced Cloudflare Access middleware with JWT, whitelist, and sessions.

    This middleware provides complete authentication with:
    - JWT token validation (secure)
    - Email whitelist authorization
    - User tier assignment
    - Session management
    - Development mode support

    Example:
        middleware = CloudflareAuthMiddlewareEnhanced(
            app=app,
            whitelist_validator=validator,
            session_manager=session_manager,
            excluded_paths=["/health", "/docs"],
            enable_sessions=True
        )
    """

    def __init__(
        self,
        app: Any,
        settings: CloudflareSettings | None = None,
        validator: CloudflareJWTValidator | None = None,
        whitelist_validator: EmailWhitelistValidator | None = None,
        session_manager: SimpleSessionManager | None = None,
        excluded_paths: list[str] | None = None,
        enable_sessions: bool = True,
        require_auth: bool = True,
        enable_rate_limiting: bool = True,
        rate_limit_attempts: int = 5,
        rate_limit_window: int = 60,
    ) -> None:
        """Initialize enhanced authentication middleware.

        Args:
            app: ASGI application
            settings: Cloudflare configuration settings
            validator: JWT token validator
            whitelist_validator: Email whitelist validator (required)
            session_manager: Session manager instance
            excluded_paths: Paths to exclude from authentication
            enable_sessions: Whether to use session cookies
            require_auth: Whether authentication is required
            enable_rate_limiting: Whether to enable rate limiting (default: True)
            rate_limit_attempts: Max authentication attempts per window (default: 5)
            rate_limit_window: Rate limit window in seconds (default: 60)
        """
        super().__init__(app)
        self.settings = settings or get_cloudflare_settings()
        self.jwt_validator = validator or CloudflareJWTValidator(self.settings)
        self.whitelist_validator = whitelist_validator
        self.session_manager = session_manager or SimpleSessionManager()
        self.excluded_paths = excluded_paths or []
        self.enable_sessions = enable_sessions
        self.require_auth = require_auth

        # Rate limiting
        self.enable_rate_limiting = enable_rate_limiting
        if enable_rate_limiting:
            self.rate_limiter = InMemoryRateLimiter(
                max_attempts=rate_limit_attempts,
                window_seconds=rate_limit_window,
            )
        else:
            self.rate_limiter = None

        # CSRF protection for sessions
        if enable_sessions:
            self.csrf_protection = CSRFProtection()
        else:
            self.csrf_protection = None

        # Validate configuration
        if (
            self.settings.cloudflare_enabled
            and require_auth
            and not whitelist_validator
        ):
            logger.warning(
                "No whitelist validator provided - all authenticated users will be allowed"
            )

        logger.info(
            "Initialized enhanced Cloudflare auth middleware "
            "(JWT enabled=%s, sessions=%s, whitelist=%s, rate_limiting=%s)",
            self.settings.cloudflare_enabled,
            self.enable_sessions,
            whitelist_validator is not None,
            self.enable_rate_limiting,
        )

    def _is_path_excluded(self, path: str) -> bool:
        """Check if a path should bypass authentication.

        Args:
            path: Request path to check

        Returns:
            True if path is excluded from auth
        """
        return any(
            path == excluded or path.startswith(excluded.rstrip("/") + "/")
            for excluded in self.excluded_paths
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request with enhanced authentication.

        Authentication flow:
        1. Check if path is excluded
        2. Check for existing valid session
        3. Validate JWT token from Cloudflare
        4. Check email whitelist
        5. Determine user tier and privileges
        6. Create/update session
        7. Inject user into request.state

        Args:
            request: Incoming request
            call_next: Next middleware/endpoint

        Returns:
            Response from application
        """
        # Skip authentication for excluded paths
        if self._is_path_excluded(request.url.path):
            logger.debug("Path excluded from auth: %s", request.url.path)
            return await call_next(request)

        # Handle development mode (no Cloudflare)
        if not self.settings.cloudflare_enabled:
            logger.debug("Cloudflare authentication disabled (dev mode)")
            if not self.require_auth:
                request.state.user = None
            return await call_next(request)

        # Authenticate the request
        try:
            user = await self._authenticate_request(request)
            request.state.user = user

            response = await call_next(request)

            # Set session cookie if needed
            if (
                self.enable_sessions
                and user
                and user.session_id
                and user.session_id != request.cookies.get("session_id")
            ):
                self._set_session_cookie(response, user.session_id)

            return response

        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Unexpected error during authentication")
            if self.require_auth:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Authentication service error",
                ) from e
            request.state.user = None
            return await call_next(request)

    def _check_rate_limit(self, request: Request) -> None:
        """Check rate limit and raise HTTPException if exceeded."""
        if not (self.enable_rate_limiting and self.rate_limiter):
            return

        client_ip = get_client_ip(request)
        if self.rate_limiter.is_allowed(client_ip):
            return

        retry_after = self.rate_limiter.get_retry_after(client_ip)
        logger.warning(
            "Rate limit exceeded for IP: %s (path: %s)",
            sanitize_ip(client_ip),
            sanitize_path(request.url.path),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    def _authenticate_from_session(self, request: Request) -> CloudflareUser | None:
        """Attempt to authenticate from existing session."""
        if not self.enable_sessions:
            return None

        session_id = request.cookies.get("session_id")
        if not session_id:
            return None

        session = self.session_manager.get_session(session_id)
        if not session:
            return None

        user = self._user_from_session(session, session_id)
        logger.debug("Authenticated from session: %s", user.email)
        return user

    def _handle_missing_token(self, request: Request) -> None:
        """Handle missing JWT token - raise if auth required."""
        if not self.require_auth:
            return

        self._record_failed_attempt(request)
        if self.settings.log_auth_failures:
            logger.warning(
                "Missing JWT header: %s (path: %s, ip: %s)",
                self.settings.jwt_header_name,
                sanitize_path(request.url.path),
                sanitize_ip(get_client_ip(request)),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _validate_token_size(self, jwt_token: str, request: Request) -> bool:
        """Validate JWT token size. Returns True if valid."""
        if len(jwt_token) <= 8192:
            return True

        logger.warning(
            "JWT token too large: %d bytes (path: %s, ip: %s)",
            len(jwt_token),
            sanitize_path(request.url.path),
            sanitize_ip(get_client_ip(request)),
        )
        if self.require_auth:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="JWT token too large",
            )
        return False

    def _record_failed_attempt(self, request: Request) -> None:
        """Record a failed authentication attempt for rate limiting."""
        if self.enable_rate_limiting and self.rate_limiter:
            self.rate_limiter.record_attempt(get_client_ip(request))

    def _handle_jwt_validation_error(self, error: ValueError, request: Request) -> None:
        """Handle JWT validation errors."""
        self._record_failed_attempt(request)

        if self.settings.log_auth_failures:
            logger.warning(
                "JWT validation failed: %s (path: %s, ip: %s)",
                str(error),
                sanitize_path(request.url.path),
                sanitize_ip(get_client_ip(request)),
            )

        if self.require_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from error

    def _check_whitelist(self, email: str) -> UserTier:
        """Check whitelist authorization and return user tier."""
        if not self.whitelist_validator:
            return UserTier.FULL

        if not self.whitelist_validator.is_authorized(email):
            logger.warning(
                "Unauthorized email attempted access: %s",
                sanitize_email(email),
            )
            if self.require_auth:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Email {email} not authorized",
                )
            msg = "Email not authorized"
            raise ValueError(msg)

        try:
            return self.whitelist_validator.get_user_tier(email)
        except ValueError:
            return UserTier.LIMITED

    def _create_session_if_enabled(
        self, claims: Any, user_tier: UserTier, request: Request
    ) -> str | None:
        """Create session if sessions are enabled."""
        if not self.enable_sessions:
            return None

        return self.session_manager.create_session(
            email=claims.email,
            is_admin=user_tier.has_admin_privileges,
            user_tier=user_tier.value,
            cf_context={
                "cf_ray": request.headers.get("cf-ray"),
                "cf_country": request.headers.get("cf-ipcountry"),
            },
        )

    async def _authenticate_request(self, request: Request) -> CloudflareUser | None:
        """Authenticate request using JWT and whitelist.

        Args:
            request: Incoming request

        Returns:
            CloudflareUser object if authenticated, None if optional

        Raises:
            HTTPException: If authentication fails and is required
        """
        self._check_rate_limit(request)

        # Check for existing session first
        session_user = self._authenticate_from_session(request)
        if session_user:
            return session_user

        # Extract JWT token
        jwt_token = request.headers.get(self.settings.jwt_header_name)
        if not jwt_token:
            self._handle_missing_token(request)
            return None

        if not self._validate_token_size(jwt_token, request):
            return None

        # Validate JWT token
        try:
            claims = self.jwt_validator.validate_token(jwt_token)
        except ValueError as e:
            self._handle_jwt_validation_error(e, request)
            return None

        # Check whitelist and get tier
        try:
            user_tier = self._check_whitelist(claims.email)
        except ValueError:
            return None

        # Create session if enabled
        session_id = self._create_session_if_enabled(claims, user_tier, request)

        # Create user object
        user = CloudflareUser.from_jwt_claims(
            claims=claims,
            user_tier=user_tier,
            is_admin=user_tier.has_admin_privileges,
            session_id=session_id,
        )

        logger.info(
            "User authenticated: %s (tier: %s, admin: %s)",
            sanitize_email(user.email),
            user_tier.value,
            user.is_admin,
        )

        return user

    def _user_from_session(
        self, session: dict[str, Any], session_id: str
    ) -> CloudflareUser:
        """Recreate CloudflareUser from session data.

        Args:
            session: Session data dictionary
            session_id: Session identifier

        Returns:
            CloudflareUser instance
        """
        from cloudflare_auth.models import CloudflareJWTClaims

        # Create minimal claims for session-based auth
        issuer = self.settings.issuer or "session-auth"
        claims = CloudflareJWTClaims(
            email=session["email"],
            iss=issuer,
            aud=[self.settings.cloudflare_audience_tag],
            sub=session.get("email", ""),
            iat=int(session["created_at"].timestamp()),
            exp=int(session["last_accessed"].timestamp())
            + self.session_manager.session_timeout,
        )

        tier = UserTier.from_string(session.get("user_tier", "limited"))

        return CloudflareUser.from_jwt_claims(
            claims=claims,
            user_tier=tier,
            is_admin=session.get("is_admin", False),
            session_id=session_id,
        )

    def _set_session_cookie(self, response: Response, session_id: str) -> None:
        """Set session cookie and CSRF token in response.

        Uses security settings from configuration for proper cookie attributes.

        Args:
            response: Response to modify
            session_id: Session ID to set
        """
        # Prepare cookie kwargs from settings
        # Get cookie configuration
        max_age = self.session_manager.session_timeout
        path = self.settings.cookie_path
        secure = self.settings.cookie_secure
        samesite = self.settings.cookie_samesite
        domain = self.settings.cookie_domain

        # Set session cookie (httponly for security)
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            max_age=max_age,
            path=path,
            secure=secure,
            samesite=samesite,
            domain=domain,
        )

        # Set CSRF token cookie (NOT httponly, needs to be readable by JS)
        if self.csrf_protection:
            csrf_token = self.csrf_protection.generate_token(session_id)
            response.set_cookie(
                key="csrf_token",
                value=csrf_token,
                httponly=False,  # Must be readable by JavaScript
                max_age=max_age,
                path=path,
                secure=secure,
                samesite=samesite,
                domain=domain,
            )


def setup_cloudflare_auth_enhanced(
    app: Any,
    whitelist: list[str] | None = None,
    admin_emails: list[str] | None = None,
    full_users: list[str] | None = None,
    limited_users: list[str] | None = None,
    excluded_paths: list[str] | None = None,
    enable_sessions: bool = True,
    require_auth: bool = True,
    session_timeout: int = 3600,
    settings: CloudflareSettings | None = None,
) -> None:
    """Setup enhanced Cloudflare authentication with all features.

    This is the recommended setup function that provides:
    - JWT validation for security
    - Email whitelist authorization
    - User tier management
    - Session support
    - Development mode

    Args:
        app: FastAPI application
        whitelist: List of allowed emails/domains (e.g., ["user@example.com", "@company.com"])
        admin_emails: List of admin emails
        full_users: List of full-tier users
        limited_users: List of limited-tier users
        excluded_paths: Paths to exclude from auth
        enable_sessions: Whether to use session cookies
        require_auth: Whether authentication is required
        session_timeout: Session timeout in seconds
        settings: Optional CloudflareSettings instance

    Returns:
        None - middleware is added directly to the app

    Example:
        app = FastAPI()
        setup_cloudflare_auth_enhanced(
            app,
            whitelist=["user@example.com", "@company.com"],
            admin_emails=["admin@company.com"],
            full_users=["@company.com"],
            excluded_paths=["/health", "/docs"],
            enable_sessions=True
        )
    """
    settings = settings or get_cloudflare_settings()

    # Create whitelist validator if whitelist provided
    whitelist_validator = None
    if whitelist:
        whitelist_validator = EmailWhitelistValidator(
            whitelist=whitelist,
            admin_emails=admin_emails or [],
            full_users=full_users or [],
            limited_users=limited_users or [],
        )

        # Log whitelist stats
        stats = whitelist_validator.get_whitelist_stats()
        logger.info(
            "Whitelist configured: %d entries, %d domains, %d admins",
            stats["total_entries"],
            len(stats["domains"]),
            stats["admin_emails"],
        )

        # Check for warnings
        warnings = whitelist_validator.validate_whitelist_config()
        for warning in warnings:
            logger.warning("Whitelist config: %s", warning)

    # Create session manager
    session_manager = None
    if enable_sessions:
        session_manager = SimpleSessionManager(session_timeout=session_timeout)

    # Create JWT validator
    jwt_validator = CloudflareJWTValidator(settings)

    # Default excluded paths
    default_excluded = [
        "/health",
        "/healthz",
        "/ready",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    ]

    all_excluded = list(set(default_excluded + (excluded_paths or [])))

    # Add middleware
    app.add_middleware(
        CloudflareAuthMiddlewareEnhanced,
        settings=settings,
        validator=jwt_validator,
        whitelist_validator=whitelist_validator,
        session_manager=session_manager,
        excluded_paths=all_excluded,
        enable_sessions=enable_sessions,
        require_auth=require_auth,
    )

    logger.info(
        "Enhanced Cloudflare authentication configured "
        "(whitelist=%s, sessions=%s, excluded_paths=%d)",
        whitelist_validator is not None,
        enable_sessions,
        len(all_excluded),
    )


# FastAPI dependencies
def get_current_user(request: Request) -> CloudflareUser:
    """FastAPI dependency to get current authenticated user.

    Args:
        request: FastAPI request

    Returns:
        CloudflareUser object

    Raises:
        HTTPException: If user is not authenticated

    Example:
        @app.get("/me")
        async def get_me(user: CloudflareUser = Depends(get_current_user)):
            return {"email": user.email}
    """
    user = getattr(request.state, "user", None)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_user_optional(request: Request) -> CloudflareUser | None:
    """FastAPI dependency for optional authentication.

    Args:
        request: FastAPI request

    Returns:
        CloudflareUser or None

    Example:
        @app.get("/info")
        async def info(user: CloudflareUser | None = Depends(get_current_user_optional)):
            if user:
                return {"message": f"Hello {user.email}"}
            return {"message": "Hello anonymous"}
    """
    return getattr(request.state, "user", None)


def require_admin(request: Request) -> CloudflareUser:
    """FastAPI dependency requiring admin privileges.

    Args:
        request: FastAPI request

    Returns:
        CloudflareUser object

    Raises:
        HTTPException: If not authenticated or not admin

    Example:
        @app.get("/admin")
        async def admin_panel(user: CloudflareUser = Depends(require_admin)):
            return {"message": "Admin panel"}
    """
    user = get_current_user(request)

    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    return user


def require_tier(minimum_tier: UserTier) -> Callable:
    """Create a dependency that requires a minimum user tier.

    Args:
        minimum_tier: Minimum required tier

    Returns:
        Dependency function

    Example:
        require_full = require_tier(UserTier.FULL)

        @app.get("/premium")
        async def premium(user: CloudflareUser = Depends(require_full)):
            return {"message": "Premium content"}
    """

    def dependency(request: Request) -> CloudflareUser:
        user = get_current_user(request)

        tier_order = {
            UserTier.LIMITED: 0,
            UserTier.FULL: 1,
            UserTier.ADMIN: 2,
        }

        if tier_order[user.user_tier] < tier_order[minimum_tier]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Minimum tier {minimum_tier.value} required",
            )

        return user

    return dependency
