"""Tests for CloudflareJWTValidator security hardening.

These tests cover behaviour added in the security-hardening pass:
- Constructor algorithm allowlist (rejects ``none``, HS*).
- Required-claim validation.
- ``get_unverified_claims`` warning + safe fallback.
- Configuration property (``is_configured``).
- Configured-but-unconfigured-domain warning path.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from cloudflare_auth.config import CloudflareSettings
from cloudflare_auth.validators import (
    _ALLOWED_JWT_ALGORITHMS,
    CloudflareJWTValidator,
)


def _settings(**overrides) -> CloudflareSettings:
    """Build a CloudflareSettings instance with a populated team domain."""
    defaults = {
        "cloudflare_team_domain": "myteam",
        "cloudflare_audience_tag": "aud-123",
    }
    defaults.update(overrides)
    return CloudflareSettings(**defaults)


class TestAlgorithmAllowlist:
    """Constructor must reject unsafe / non-asymmetric algorithms."""

    @pytest.mark.parametrize(
        "alg",
        ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"],
    )
    def test_accepts_asymmetric_algorithms(self, alg):
        """Each algorithm in the allowlist must be accepted at construction."""
        assert alg in _ALLOWED_JWT_ALGORITHMS
        v = CloudflareJWTValidator(_settings(jwt_algorithm=alg))
        assert v.settings.jwt_algorithm == alg

    @pytest.mark.parametrize(
        "alg",
        ["none", "None", "NONE", "HS256", "HS384", "HS512", "", "rs256", "garbage"],
    )
    def test_rejects_unsafe_or_unknown_algorithms(self, alg):
        """``none``, HS*, lowercase, and unknown values must be rejected."""
        with pytest.raises(ValueError, match="Unsupported JWT algorithm"):
            CloudflareJWTValidator(_settings(jwt_algorithm=alg))


class TestConstructorConfigState:
    """Validator captures configuration state and warns when incomplete."""

    def test_missing_team_domain_warns_and_jwks_client_none(self, caplog):
        """Without a team domain, JWKS client is None and a warning is logged."""
        caplog.set_level(logging.WARNING)
        v = CloudflareJWTValidator(
            CloudflareSettings(
                cloudflare_team_domain="",
                cloudflare_audience_tag="aud",
            )
        )
        assert v.jwks_client is None
        assert any(
            "team domain not configured" in record.message.lower()
            for record in caplog.records
        )

    def test_is_configured_true_when_complete(self):
        """``is_configured`` is True only when all required settings are present."""
        v = CloudflareJWTValidator(_settings())
        assert v.is_configured is True

    def test_is_configured_false_without_audience(self):
        """Missing audience tag means the validator is not fully configured."""
        v = CloudflareJWTValidator(_settings(cloudflare_audience_tag=""))
        assert v.is_configured is False


class TestValidateTokenWithoutJWKS:
    """``validate_token`` raises RuntimeError when no JWKS client is configured."""

    def test_validate_token_raises_runtime_error_when_unconfigured(self):
        """Calling validate_token without a JWKS client must fail loudly."""
        v = CloudflareJWTValidator(
            CloudflareSettings(
                cloudflare_team_domain="",
                cloudflare_audience_tag="aud",
            )
        )
        with pytest.raises(RuntimeError, match="not configured"):
            v.validate_token("token.value.here")


class TestRequiredClaimsValidation:
    """``_validate_required_claims`` enforces presence of standard claims."""

    def test_complete_payload_passes(self, sample_jwt_payload):
        v = CloudflareJWTValidator(_settings())
        # Should not raise
        v._validate_required_claims(sample_jwt_payload)

    @pytest.mark.parametrize(
        "missing",
        ["email", "iss", "aud", "sub", "iat", "exp"],
    )
    def test_missing_claim_raises(self, sample_jwt_payload, missing):
        sample_jwt_payload.pop(missing)
        v = CloudflareJWTValidator(_settings())
        with pytest.raises(ValueError, match="Missing required JWT claims"):
            v._validate_required_claims(sample_jwt_payload)


class TestGetUnverifiedClaims:
    """``get_unverified_claims`` returns claims, logs a warning, and never raises."""

    def test_returns_claims_and_logs_warning_for_valid_token(
        self, valid_jwt_payload, caplog
    ):
        """A parseable token returns its claims; a warning is always logged."""
        import jwt as pyjwt

        token = pyjwt.encode(valid_jwt_payload, "secret", algorithm="HS256")
        v = CloudflareJWTValidator(_settings())

        caplog.set_level(logging.WARNING)
        claims = v.get_unverified_claims(token)

        assert claims["email"] == valid_jwt_payload["email"]
        assert claims["iss"] == valid_jwt_payload["iss"]
        assert any(
            "get_unverified_claims" in r.message for r in caplog.records
        ), "expected warning log on every call to get_unverified_claims"

    def test_returns_empty_dict_on_malformed_token(self, caplog):
        """A malformed token must not propagate -- returns ``{}``."""
        v = CloudflareJWTValidator(_settings())
        caplog.set_level(logging.WARNING)
        result = v.get_unverified_claims("not.a.real.token")
        assert result == {}


class TestRefreshKeys:
    """``refresh_keys`` replaces the JWKS client without crashing."""

    def test_refresh_keys_creates_new_client(self):
        v = CloudflareJWTValidator(_settings())
        original = v.jwks_client
        v.refresh_keys()
        assert v.jwks_client is not None
        # New PyJWKClient instance, not the same object
        assert v.jwks_client is not original
        assert v._last_key_refresh is not None


class TestValidateTokenDecodeOptions:
    """``validate_token`` passes the hardened option set to ``jwt.decode``."""

    def test_decode_options_enforce_signature_exp_nbf_iat_and_require(
        self, valid_jwt_payload
    ):
        """Verify the security-relevant options are spelled out on every call."""
        v = CloudflareJWTValidator(_settings())

        fake_signing_key = MagicMock(key="fake-key")
        v.jwks_client = MagicMock()
        v.jwks_client.get_signing_key_from_jwt.return_value = fake_signing_key

        with patch(
            "cloudflare_auth.validators.jwt.decode",
            return_value=valid_jwt_payload,
        ) as mock_decode:
            v.validate_token("fake.jwt.token")

        # ``options`` is passed as a kwarg
        call_kwargs = mock_decode.call_args.kwargs
        opts = call_kwargs["options"]
        assert opts["verify_signature"] is True
        assert opts["verify_exp"] is True
        assert opts["verify_nbf"] is True
        assert opts["verify_iat"] is True
        assert "exp" in opts["require"]
        assert "iat" in opts["require"]
        assert "iss" in opts["require"]
        assert "sub" in opts["require"]
        assert "aud" in opts["require"]
        # ``algorithms`` is constrained to the configured (validated) value
        assert call_kwargs["algorithms"] == [v.settings.jwt_algorithm]
        # Some leeway is allowed for clock skew
        assert call_kwargs["leeway"] > 0


class TestValidateTokenErrorMapping:
    """PyJWT-specific exceptions are mapped to ``ValueError`` with a message."""

    @pytest.mark.parametrize(
        ("exc_cls", "expected_substring"),
        [
            ("ExpiredSignatureError", "expired"),
            ("ImmatureSignatureError", "not yet valid"),
            ("InvalidAudienceError", "audience"),
            ("InvalidIssuerError", "issuer"),
            ("InvalidAlgorithmError", "algorithm"),
            ("InvalidSignatureError", "signature"),
            ("DecodeError", "format"),
        ],
    )
    def test_pyjwt_exceptions_become_value_errors(self, exc_cls, expected_substring):
        import jwt as pyjwt

        v = CloudflareJWTValidator(_settings())
        v.jwks_client = MagicMock()
        v.jwks_client.get_signing_key_from_jwt.return_value = MagicMock(key="k")

        with patch(
            "cloudflare_auth.validators.jwt.decode",
            side_effect=getattr(pyjwt, exc_cls)("boom"),
        ), pytest.raises(ValueError, match=expected_substring):
            v.validate_token("any.jwt.token")
