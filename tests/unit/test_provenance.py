from provenance.verifier import generate_provenance_signature, verify_provenance

def test_generate_and_verify_valid():
    operation = "get_downstream_status"
    arguments = {"test": 123}
    sig = generate_provenance_signature(operation, arguments)
    
    decision = verify_provenance(operation, arguments, sig)
    assert decision.decision == "ALLOW"
    assert decision.verification == "VALID"
    assert decision.source == "mcp_internal"

def test_verify_missing():
    decision = verify_provenance("get_downstream_status", {}, None)
    assert decision.decision == "BLOCK"
    assert decision.verification == "INVALID"
    assert decision.source == "unknown"
    assert "missing" in decision.reason

def test_verify_invalid():
    decision = verify_provenance("get_downstream_status", {}, "random_invalid_sig")
    assert decision.decision == "BLOCK"
    assert decision.verification == "INVALID"
    assert decision.source == "unknown"
    
def test_verify_tampered():
    # Sign one payload
    sig = generate_provenance_signature("get_downstream_status", {})
    
    # Try to use that signature for another payload
    decision = verify_provenance("create_record", {"name": "evil", "value": "payload"}, sig)
    assert decision.decision == "BLOCK"
    assert decision.verification == "INVALID"
    assert decision.source == "unknown"


def test_provenance_explicit_valid_secret():
    """Valid explicitly configured secret succeeds and verifies strictly."""
    import os
    from unittest.mock import patch
    from provenance.verifier import get_provenance_secret, generate_provenance_signature, verify_provenance

    custom_secret = "prod-tier-secret-key-99887766"
    with patch.dict(os.environ, {"VETO_PROVENANCE_SECRET": custom_secret}):
        assert get_provenance_secret() == custom_secret.encode("utf-8")

        op = "create_record"
        args = {"name": "secure_record", "value": "test"}
        req_id = "REQ-SEC-001"
        sig = generate_provenance_signature(op, args, req_id)

        # Verification with matching secret must pass
        decision = verify_provenance(op, args, sig, req_id)
        assert decision.decision == "ALLOW"
        assert decision.verification == "VALID"
        assert decision.source == "mcp_internal"
        assert decision.reason == "trusted_invocation"

        # Verification with altered secret must fail closed
        with patch.dict(os.environ, {"VETO_PROVENANCE_SECRET": "different-secret-key"}):
            tampered_decision = verify_provenance(op, args, sig, req_id)
            assert tampered_decision.decision == "BLOCK"
            assert tampered_decision.verification == "INVALID"
            assert tampered_decision.reason == "tampered_or_invalid_provenance_signature"


def test_provenance_empty_secret_fails_closed():
    """Empty or whitespace-only provenance secret must fail closed and never fall back."""
    import os
    import pytest
    from unittest.mock import patch
    from provenance.verifier import (
        get_provenance_secret,
        generate_provenance_signature,
        verify_provenance,
        ProvenanceSecretConfigurationError,
    )

    for empty_val in ["", "   ", "\t\n"]:
        with patch.dict(os.environ, {"VETO_PROVENANCE_SECRET": empty_val}):
            # get_provenance_secret must raise
            with pytest.raises(ProvenanceSecretConfigurationError, match="empty or contains only whitespace"):
                get_provenance_secret()

            # generate_provenance_signature must raise
            with pytest.raises(ProvenanceSecretConfigurationError):
                generate_provenance_signature("get_downstream_status", {})

            # verify_provenance must fail closed safely
            decision = verify_provenance("get_downstream_status", {}, "some_sig")
            assert decision.decision == "BLOCK"
            assert decision.verification == "INVALID"
            assert decision.reason == "provenance_secret_not_configured"


def test_provenance_missing_secret_strict_fails_closed():
    """Missing secret with fallback disabled must fail closed."""
    import os
    import pytest
    from unittest.mock import patch
    from provenance.verifier import (
        get_provenance_secret,
        generate_provenance_signature,
        verify_provenance,
        ProvenanceSecretConfigurationError,
    )

    env_overrides = {"VETO_ALLOW_DEV_FALLBACK": "0"}
    with patch.dict(os.environ, env_overrides):
        os.environ.pop("VETO_PROVENANCE_SECRET", None)

        with pytest.raises(ProvenanceSecretConfigurationError, match="development fallback is disabled"):
            get_provenance_secret()

        with pytest.raises(ProvenanceSecretConfigurationError):
            generate_provenance_signature("get_downstream_status", {})

        decision = verify_provenance("get_downstream_status", {}, "some_sig")
        assert decision.decision == "BLOCK"
        assert decision.verification == "INVALID"
        assert decision.reason == "provenance_secret_not_configured"


def test_provenance_missing_secret_production_fails_closed():
    """Missing secret in production mode must fail closed even if fallback flag was not disabled."""
    import os
    import pytest
    from unittest.mock import patch
    from provenance.verifier import (
        get_provenance_secret,
        verify_provenance,
        ProvenanceSecretConfigurationError,
    )

    with patch.dict(os.environ, {"VETO_ENVIRONMENT": "production"}):
        os.environ.pop("VETO_PROVENANCE_SECRET", None)

        with pytest.raises(ProvenanceSecretConfigurationError):
            get_provenance_secret()

        decision = verify_provenance("get_downstream_status", {}, "some_sig")
        assert decision.decision == "BLOCK"
        assert decision.verification == "INVALID"
        assert decision.reason == "provenance_secret_not_configured"


def test_provenance_dev_fallback_mode():
    """Development fallback is clearly distinct, non-silent, and distinct from old dummy default."""
    import os
    import logging
    from unittest.mock import patch
    from provenance.verifier import (
        get_provenance_secret,
        generate_provenance_signature,
        verify_provenance,
        DEV_FALLBACK_SECRET,
    )

    with patch.dict(os.environ, {"VETO_ENVIRONMENT": "local", "VETO_ALLOW_DEV_FALLBACK": "1"}):
        os.environ.pop("VETO_PROVENANCE_SECRET", None)

        secret = get_provenance_secret()
        assert secret == DEV_FALLBACK_SECRET
        assert secret != b"default-dev-secret-12345"
        assert b"insecure" in secret
        assert b"never-use-in-production" in secret

        # Can generate and verify in local development
        sig = generate_provenance_signature("get_downstream_status", {})
        decision = verify_provenance("get_downstream_status", {}, sig)
        assert decision.decision == "ALLOW"
        assert decision.verification == "VALID"


def test_gateway_fail_closed_on_unconfigured_secret(monkeypatch):
    """The gateway must reject requests and fail closed before downstream execution when secret is invalid."""
    import os
    from unittest.mock import patch, MagicMock
    from fastapi.testclient import TestClient
    from gateway.gateway import app

    client = TestClient(app)

    # When provenance secret is empty string
    with patch.dict(os.environ, {"VETO_PROVENANCE_SECRET": ""}):
        response = client.post(
            "/gateway/execute",
            json={
                "operation": "get_downstream_status",
                "arguments": {},
                "provenance_signature": "dummy_sig",
            },
        )
        assert response.status_code == 403
        data = response.json()
        assert data["detail"]["decision"] == "BLOCK"
        assert data["detail"]["reason"] == "provenance_secret_not_configured"

    # When provenance secret is missing in strict / production mode
    with patch.dict(os.environ, {"VETO_ENVIRONMENT": "production"}):
        os.environ.pop("VETO_PROVENANCE_SECRET", None)
        response = client.post(
            "/gateway/execute",
            json={
                "operation": "get_downstream_status",
                "arguments": {},
                "provenance_signature": "dummy_sig",
            },
        )
        assert response.status_code == 403
        data = response.json()
        assert data["detail"]["decision"] == "BLOCK"
        assert data["detail"]["reason"] == "provenance_secret_not_configured"
