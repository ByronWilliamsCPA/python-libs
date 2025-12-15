"""Redis-based session management for production use.

This module provides a production-ready Redis-based session manager
with persistence, scalability, and security features.

⚠️ IMPORTANT: This requires redis package to be installed:
    pip install redis>=5.0.0

Key Features:
    - Persistent session storage
    - Shared across multiple application instances
    - Automatic expiration with Redis TTL
    - Session fixation protection
    - Atomic operations

Dependencies:
    - redis: For Redis client
    - json: For session serialization
    - secrets: For secure session ID generation

Example:
    from cloudflare_auth.redis_sessions import RedisSessionManager

    session_manager = RedisSessionManager(
        redis_url="redis://localhost:6379/0",
        session_timeout=3600
    )

    # Use with middleware
    setup_cloudflare_auth_enhanced(
        app,
        session_manager=session_manager,
        enable_sessions=True
    )
"""

import json
import logging
import secrets
from datetime import UTC, datetime
from typing import Any

_redis_available: bool
try:
    import redis

    _redis_available = True
except ImportError:
    _redis_available = False
    redis = None  # type: ignore[assignment]

# Expose as uppercase for backwards compatibility
REDIS_AVAILABLE = _redis_available

logger = logging.getLogger(__name__)


class RedisSessionManager:
    """Production-ready Redis-based session manager.

    This manager stores sessions in Redis, providing:
    - Persistence across application restarts
    - Shared state across multiple instances
    - Automatic expiration using Redis TTL
    - Session fixation protection
    - High performance and scalability

    Requirements:
        pip install redis>=5.0.0

    Example:
        manager = RedisSessionManager(
            redis_url="redis://localhost:6379/0",
            session_timeout=3600,
            key_prefix="cf_auth"
        )

        session_id = manager.create_session(
            email="user@example.com",
            is_admin=True,
            user_tier="admin"
        )
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        session_timeout: int = 3600,
        key_prefix: str = "cf_auth_session",
    ) -> None:
        """Initialize Redis session manager.

        Args:
            redis_url: Redis connection URL
            session_timeout: Session timeout in seconds (default: 1 hour)
            key_prefix: Prefix for Redis keys (default: "cf_auth_session")

        Raises:
            ImportError: If redis package is not installed
            redis.ConnectionError: If cannot connect to Redis
        """
        if not REDIS_AVAILABLE or redis is None:
            msg = (
                "Redis package is required for RedisSessionManager. "
                "Install with: pip install redis>=5.0.0"
            )
            raise ImportError(msg)

        self.session_timeout = session_timeout
        self.key_prefix = key_prefix

        # Initialize Redis client
        self.redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
        )

        # Test connection
        try:
            self.redis_client.ping()
            logger.info(
                "Initialized Redis session manager (timeout=%ds, prefix=%s)",
                session_timeout,
                key_prefix,
            )
        except redis.ConnectionError:
            logger.exception("Failed to connect to Redis")
            raise

    def _make_key(self, session_id: str) -> str:
        """Generate Redis key for session.

        Args:
            session_id: Session identifier

        Returns:
            Redis key with prefix
        """
        return f"{self.key_prefix}:{session_id}"

    def create_session(
        self,
        email: str,
        is_admin: bool,
        user_tier: str,
        cf_context: dict[str, Any] | None = None,
    ) -> str:
        """Create a new session in Redis.

        Args:
            email: User email address
            is_admin: Whether user has admin privileges
            user_tier: User tier (admin, full, limited)
            cf_context: Additional Cloudflare context

        Returns:
            Session ID (cryptographically secure random token)

        Example:
            session_id = manager.create_session(
                email="user@example.com",
                is_admin=False,
                user_tier="full",
                cf_context={"cf_ray": "abc123"}
            )
        """
        # Generate secure session ID
        session_id = secrets.token_urlsafe(32)

        # Prepare session data
        session_data = {
            "email": email,
            "is_admin": is_admin,
            "user_tier": user_tier,
            "created_at": datetime.now(tz=UTC).isoformat(),
            "last_accessed": datetime.now(tz=UTC).isoformat(),
            "cf_context": cf_context or {},
        }

        # Store in Redis with TTL
        key = self._make_key(session_id)
        self.redis_client.setex(key, self.session_timeout, json.dumps(session_data))

        logger.debug(
            "Created session for %s (tier: %s, admin: %s)",
            email,
            user_tier,
            is_admin,
        )

        return session_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session data from Redis.

        This method automatically:
        - Returns None if session doesn't exist or expired
        - Updates last_accessed timestamp
        - Refreshes TTL

        Args:
            session_id: Session identifier

        Returns:
            Session data if valid, None if expired or not found
        """
        if not session_id:
            return None

        key = self._make_key(session_id)

        # Get session data
        session_data_json = self.redis_client.get(key)
        if not session_data_json:
            return None

        try:
            # Cast from ResponseT to expected type
            session_json_str = (
                session_data_json
                if isinstance(session_data_json, (str, bytes, bytearray))
                else str(session_data_json)
            )
            session_data = json.loads(session_json_str)

            # Update last accessed timestamp
            session_data["last_accessed"] = datetime.now(tz=UTC).isoformat()

            # Update in Redis and refresh TTL
            self.redis_client.setex(key, self.session_timeout, json.dumps(session_data))

            # Parse datetime objects
            session_data["created_at"] = datetime.fromisoformat(
                session_data["created_at"]
            )
            session_data["last_accessed"] = datetime.fromisoformat(
                session_data["last_accessed"]
            )

            return session_data

        except (json.JSONDecodeError, ValueError) as e:
            logger.exception("Failed to decode session data: %s", e)
            # Delete corrupted session
            self.redis_client.delete(key)
            return None

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate (delete) a session from Redis.

        Args:
            session_id: Session to invalidate

        Returns:
            True if session was found and deleted
        """
        key = self._make_key(session_id)
        deleted = self.redis_client.delete(key)

        if deleted:
            logger.debug("Invalidated session %s", session_id[:8] + "...")
            return True

        return False

    def refresh_session(self, session_id: str) -> bool:
        """Refresh a session's expiration time.

        Args:
            session_id: Session to refresh

        Returns:
            True if session was found and refreshed
        """
        key = self._make_key(session_id)

        # Check if session exists
        if not self.redis_client.exists(key):
            return False

        # Refresh TTL
        refreshed = self.redis_client.expire(key, self.session_timeout)

        if refreshed:
            logger.debug("Refreshed session %s", session_id[:8] + "...")
            return True

        return False

    def get_session_count(self) -> int:
        """Get the current number of active sessions.

        Returns:
            Number of active sessions
        """
        pattern = f"{self.key_prefix}:*"
        keys = self.redis_client.keys(pattern)
        # keys() returns a list of keys; cast for type checker
        key_list: list[str] = list(keys) if hasattr(keys, "__iter__") else []  # type: ignore[arg-type]
        return len(key_list)

    def get_user_sessions(self, email: str) -> list[str]:
        """Get all session IDs for a specific user.

        Note: This operation can be expensive on large datasets.

        Args:
            email: User email address

        Returns:
            List of session IDs for the user
        """
        pattern = f"{self.key_prefix}:*"
        keys = self.redis_client.keys(pattern)
        # Cast keys for type checker - keys() returns iterable in sync client
        key_list: list[Any] = list(keys) if hasattr(keys, "__iter__") else []  # type: ignore[arg-type]

        user_sessions: list[str] = []
        for key in key_list:
            session_data_json = self.redis_client.get(key)
            if session_data_json:
                try:
                    # Cast from ResponseT to expected type
                    session_json_str = (
                        session_data_json
                        if isinstance(session_data_json, (str, bytes, bytearray))
                        else str(session_data_json)
                    )
                    session_data = json.loads(session_json_str)
                    if session_data.get("email") == email:
                        # Extract session ID from key
                        key_str = key if isinstance(key, str) else str(key)
                        session_id = key_str.replace(f"{self.key_prefix}:", "")
                        user_sessions.append(session_id)
                except json.JSONDecodeError:
                    continue

        return user_sessions

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions.

        Note: Redis automatically handles expiration with TTL,
        so this is a no-op for RedisSessionManager.

        Returns:
            Always returns 0 (Redis handles cleanup automatically)
        """
        # Redis automatically removes expired keys
        logger.debug("Redis handles expiration automatically (no cleanup needed)")
        return 0

    def get_stats(self) -> dict[str, Any]:
        """Get session manager statistics.

        Returns:
            Dictionary with session statistics
        """
        active_sessions = self.get_session_count()

        return {
            "total_sessions": active_sessions,
            "active_sessions": active_sessions,
            "expired_sessions": 0,  # Redis handles automatically
            "session_timeout": self.session_timeout,
            "storage_backend": "redis",
            "key_prefix": self.key_prefix,
        }

    def health_check(self) -> bool:
        """Check if Redis connection is healthy.

        Returns:
            True if Redis is reachable and responsive
        """
        try:
            result = self.redis_client.ping()
            # ping() can return Awaitable[bool] or bool depending on client type
            return bool(result) if not hasattr(result, "__await__") else False
        except Exception:  # noqa: BLE001
            # Catch any redis connection errors
            return False
