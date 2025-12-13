"""Tests for cloudflare_auth sessions module."""

import time

import pytest

from cloudflare_auth.sessions import SimpleSessionManager


class TestSimpleSessionManager:
    """Test suite for SimpleSessionManager."""

    @pytest.fixture
    def session_manager(self):
        """Create a session manager for testing."""
        return SimpleSessionManager(session_timeout=3600)

    @pytest.fixture
    def short_timeout_manager(self):
        """Create a session manager with short timeout for expiration tests."""
        return SimpleSessionManager(session_timeout=1)

    def test_create_session(self, session_manager):
        """Test creating a new session."""
        session_id = session_manager.create_session(
            email="test@example.com",
            is_admin=False,
            user_tier="full",
        )

        assert session_id is not None
        assert len(session_id) > 0

    def test_create_session_with_context(self, session_manager):
        """Test creating session with CF context."""
        cf_context = {"cf_ray": "abc123", "cf_country": "US"}
        session_id = session_manager.create_session(
            email="test@example.com",
            is_admin=True,
            user_tier="admin",
            cf_context=cf_context,
        )

        session = session_manager.get_session(session_id)
        assert session is not None
        assert session["cf_context"] == cf_context

    def test_get_session_valid(self, session_manager):
        """Test retrieving a valid session."""
        session_id = session_manager.create_session(
            email="test@example.com",
            is_admin=False,
            user_tier="full",
        )

        session = session_manager.get_session(session_id)

        assert session is not None
        assert session["email"] == "test@example.com"
        assert session["is_admin"] is False
        assert session["user_tier"] == "full"

    def test_get_session_not_found(self, session_manager):
        """Test retrieving non-existent session."""
        session = session_manager.get_session("nonexistent-session-id")

        assert session is None

    def test_get_session_empty_id(self, session_manager):
        """Test retrieving with empty session ID."""
        assert session_manager.get_session("") is None
        assert session_manager.get_session(None) is None

    def test_get_session_expired(self, short_timeout_manager):
        """Test that expired sessions return None."""
        session_id = short_timeout_manager.create_session(
            email="test@example.com",
            is_admin=False,
            user_tier="full",
        )

        # Wait for session to expire
        time.sleep(1.5)

        session = short_timeout_manager.get_session(session_id)
        assert session is None

    def test_invalidate_session(self, session_manager):
        """Test invalidating a session."""
        session_id = session_manager.create_session(
            email="test@example.com",
            is_admin=False,
            user_tier="full",
        )

        result = session_manager.invalidate_session(session_id)

        assert result is True
        assert session_manager.get_session(session_id) is None

    def test_invalidate_session_not_found(self, session_manager):
        """Test invalidating non-existent session."""
        result = session_manager.invalidate_session("nonexistent")

        assert result is False

    def test_refresh_session(self, session_manager):
        """Test refreshing a session."""
        session_id = session_manager.create_session(
            email="test@example.com",
            is_admin=False,
            user_tier="full",
        )

        initial_session = session_manager.get_session(session_id)
        initial_accessed = initial_session["last_accessed"]

        # Small delay to ensure timestamp changes
        time.sleep(0.01)

        result = session_manager.refresh_session(session_id)

        assert result is True

    def test_refresh_session_not_found(self, session_manager):
        """Test refreshing non-existent session."""
        result = session_manager.refresh_session("nonexistent")

        assert result is False

    def test_cleanup_expired_sessions(self, short_timeout_manager):
        """Test cleaning up expired sessions."""
        # Create multiple sessions
        short_timeout_manager.create_session(
            email="user1@example.com",
            is_admin=False,
            user_tier="full",
        )
        short_timeout_manager.create_session(
            email="user2@example.com",
            is_admin=False,
            user_tier="full",
        )

        # Wait for sessions to expire
        time.sleep(1.5)

        count = short_timeout_manager.cleanup_expired_sessions()

        assert count == 2
        assert short_timeout_manager.get_session_count() == 0

    def test_get_session_count(self, session_manager):
        """Test getting session count."""
        assert session_manager.get_session_count() == 0

        session_manager.create_session(
            email="user1@example.com",
            is_admin=False,
            user_tier="full",
        )
        assert session_manager.get_session_count() == 1

        session_manager.create_session(
            email="user2@example.com",
            is_admin=False,
            user_tier="full",
        )
        assert session_manager.get_session_count() == 2

    def test_get_user_sessions(self, session_manager):
        """Test getting all sessions for a user."""
        email = "test@example.com"

        # Create multiple sessions for same user
        session1 = session_manager.create_session(
            email=email,
            is_admin=False,
            user_tier="full",
        )
        session2 = session_manager.create_session(
            email=email,
            is_admin=False,
            user_tier="full",
        )

        # Create session for different user
        session_manager.create_session(
            email="other@example.com",
            is_admin=False,
            user_tier="full",
        )

        user_sessions = session_manager.get_user_sessions(email)

        assert len(user_sessions) == 2
        assert session1 in user_sessions
        assert session2 in user_sessions

    def test_get_session_info(self, session_manager):
        """Test getting safe session info."""
        session_id = session_manager.create_session(
            email="test@example.com",
            is_admin=True,
            user_tier="admin",
        )

        info = session_manager.get_session_info(session_id)

        assert info is not None
        assert info["email"] == "test@example.com"
        assert info["is_admin"] is True
        assert info["user_tier"] == "admin"
        assert "created_at" in info
        assert "last_accessed" in info
        assert "age_seconds" in info

    def test_get_session_info_not_found(self, session_manager):
        """Test getting info for non-existent session."""
        info = session_manager.get_session_info("nonexistent")

        assert info is None

    def test_get_stats(self, session_manager):
        """Test getting session statistics."""
        # Create some sessions
        session_manager.create_session(
            email="admin@example.com",
            is_admin=True,
            user_tier="admin",
        )
        session_manager.create_session(
            email="user@example.com",
            is_admin=False,
            user_tier="full",
        )

        stats = session_manager.get_stats()

        assert stats["total_sessions"] == 2
        assert stats["active_sessions"] == 2
        assert stats["session_timeout"] == 3600
        assert "sessions_by_tier" in stats

    def test_session_id_is_secure(self, session_manager):
        """Test that session IDs are cryptographically secure."""
        session_ids = set()

        for _ in range(100):
            session_id = session_manager.create_session(
                email="test@example.com",
                is_admin=False,
                user_tier="full",
            )
            # Ensure no duplicate session IDs
            assert session_id not in session_ids
            session_ids.add(session_id)

            # Session ID should be reasonably long
            assert len(session_id) >= 32
