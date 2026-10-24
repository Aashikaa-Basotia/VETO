import hmac
import hashlib
import os
import json
import logging
from pydantic import BaseModel
from typing import Dict, Any, Optional

logger = logging.getLogger("veto_provenance")

class ProvenanceDecision(BaseModel):
    decision: str
    source: str
    verification: str
    reason: str


class ProvenanceSecretConfigurationError(ValueError):
    """Raised when VETO_PROVENANCE_SECRET is missing, empty, or improperly configured."""
    pass


# Clearly designated development-only fallback that cannot be mistaken for production.
DEV_FALLBACK_SECRET = b"veto-insecure-development-only-fallback-secret-never-use-in-production"


def get_provenance_secret() -> bytes:
    """
    Retrieves and validates the HMAC provenance secret from the environment.

    Security rules:
    1. If VETO_PROVENANCE_SECRET is configured:
       - Empty or whitespace-only values fail closed immediately.
       - Valid values are encoded and returned.
    2. If VETO_PROVENANCE_SECRET is missing:
       - In production environments (VETO_ENVIRONMENT='production' or ENV='production'),
         missing secrets fail closed immediately.
       - If development fallback is explicitly disabled (VETO_ALLOW_DEV_FALLBACK='0'),
         missing secrets fail closed immediately.
       - In non-production environments with fallback enabled (default for local dev/testing),
         the clearly marked DEV_FALLBACK_SECRET is returned with a visible security warning.
    """
    raw_secret = os.environ.get("VETO_PROVENANCE_SECRET")

    if raw_secret is not None:
        stripped = raw_secret.strip()
        if not stripped:
            raise ProvenanceSecretConfigurationError(
                "VETO_PROVENANCE_SECRET is configured but is empty or contains only whitespace. "
                "A non-empty secret is required."
            )
        return raw_secret.encode("utf-8")

    # Secret is not set in environment
    env = os.environ.get("VETO_ENVIRONMENT", "").lower()
    is_production = env in ("production", "prod")

    # Check if fallback is disabled: accept VETO_ALLOW_DEV_FALLBACK or VETO_DEV_FALLBACK
    fallback_flag = os.environ.get("VETO_ALLOW_DEV_FALLBACK")
    if fallback_flag is None:
        fallback_flag = os.environ.get("VETO_DEV_FALLBACK")
    if fallback_flag is None:
        if os.environ.get("VETO_REQUIRE_PROVENANCE_SECRET", "").lower() in ("1", "true", "yes"):
            fallback_flag = "0"
        else:
            fallback_flag = "1"

    allow_fallback = fallback_flag.lower() in ("1", "true", "yes")

    if not is_production and allow_fallback:
        logger.warning(
            "[VETO][SECURITY_WARNING] VETO_PROVENANCE_SECRET is not configured in environment. "
            "Using explicit development-only fallback secret. "
            "THIS CONFIGURATION IS INSECURE AND MUST NOT BE USED IN PRODUCTION."
        )
        return DEV_FALLBACK_SECRET

    raise ProvenanceSecretConfigurationError(
        "VETO_PROVENANCE_SECRET is not configured and development fallback is disabled. "
        "Execution halted to protect downstream services."
    )


def generate_provenance_signature(operation: str, arguments: Dict[str, Any], request_id: Optional[str] = None) -> str:
    """
    Generates a deterministic HMAC signature for a request.
    Called by the trusted MCP server before sending the request to VETO.
    Raises ProvenanceSecretConfigurationError if secret is missing or invalid.
    """
    secret = get_provenance_secret()
    payload_dict = {
        "operation": operation,
        "arguments": arguments
    }
    if request_id is not None:
        payload_dict["request_id"] = request_id

    payload = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_provenance(operation: str, arguments: Dict[str, Any], provided_signature: Optional[str], request_id: Optional[str] = None) -> ProvenanceDecision:
    """
    Verifies that the request came from a trusted invocation path.
    Must fail closed on any missing, invalid, tampered signature, or unconfigured secret.
    """
    try:
        secret = get_provenance_secret()
    except ProvenanceSecretConfigurationError as e:
        logger.error(f"[VETO][PROVENANCE] Configuration error: {e}")
        return ProvenanceDecision(
            decision="BLOCK",
            source="unknown",
            verification="INVALID",
            reason="provenance_secret_not_configured"
        )

    if not provided_signature:
        return ProvenanceDecision(
            decision="BLOCK",
            source="unknown",
            verification="INVALID",
            reason="missing_provenance_signature"
        )

    payload_dict = {
        "operation": operation,
        "arguments": arguments
    }
    if request_id is not None:
        payload_dict["request_id"] = request_id

    payload = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    expected_signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()

    if hmac.compare_digest(expected_signature, provided_signature):
        return ProvenanceDecision(
            decision="ALLOW",
            source="mcp_internal",
            verification="VALID",
            reason="trusted_invocation"
        )
    else:
        return ProvenanceDecision(
            decision="BLOCK",
            source="unknown",
            verification="INVALID",
            reason="tampered_or_invalid_provenance_signature"
        )


def __getattr__(name: str) -> Any:
    """
    Supports dynamic access to VETO_PROVENANCE_SECRET for backward compatibility
    without freezing a static default at module import time.
    """
    if name == "VETO_PROVENANCE_SECRET":
        return get_provenance_secret()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
