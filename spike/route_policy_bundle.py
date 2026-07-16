"""Pure version 1 route-policy canonicalization and signature verification."""

import base64
import binascii
import hashlib
import json

import route_policy_manifest as manifest_contract


CONTRACT_VERSION = 1
SCHEMA_VERSION = 1
SHA256_HEX_LENGTH = 64
ED25519_PUBLIC_KEY_LENGTH = 32
ED25519_SIGNATURE_LENGTH = 64


class RoutePolicyBundleError(ValueError):
    """Stable signed-bundle failure shared by contract vectors."""

    def __init__(self, code, path, message, *, manifest_error_code=None):
        super().__init__(message)
        self.code = code
        self.path = path
        self.manifest_error_code = manifest_error_code


def _error(code, path, message, *, manifest_error_code=None):
    raise RoutePolicyBundleError(
        code,
        path,
        message,
        manifest_error_code=manifest_error_code,
    )


def _normalize_manifest(manifest, bundled_static_routes):
    try:
        return manifest_contract.validate_route_policy_manifest(
            manifest,
            bundled_static_routes,
        )
    except manifest_contract.RoutePolicyManifestError as error:
        suffix = "" if error.path == "$" else error.path[1:]
        _error(
            "manifest_invalid",
            f"$.manifest{suffix}",
            str(error),
            manifest_error_code=error.code,
        )


def _canonical_bytes_from_normalized(manifest):
    return json.dumps(
        manifest,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def route_policy_canonical_bytes(manifest, bundled_static_routes):
    normalized = _normalize_manifest(manifest, bundled_static_routes)
    return _canonical_bytes_from_normalized(normalized)


def route_policy_hash(manifest, bundled_static_routes):
    return hashlib.sha256(
        route_policy_canonical_bytes(manifest, bundled_static_routes)
    ).hexdigest()


def _require_schema(bundle):
    if "schema" not in bundle:
        _error("missing_field", "$.schema", "schema is required")
    schema = bundle["schema"]
    if not isinstance(schema, int) or isinstance(schema, bool):
        _error("invalid_type", "$.schema", "schema must be an integer")
    if schema != SCHEMA_VERSION:
        _error(
            "out_of_range",
            "$.schema",
            "unsupported policy bundle schema",
        )


def _decode_base64(value, *, path, label):
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _error("invalid_base64", path, f"{label} is not valid base64")


def _validate_sha256(value):
    if not isinstance(value, str):
        _error("invalid_type", "$.sha256", "policy hash must be a string")
    if len(value) != SHA256_HEX_LENGTH or any(
        character not in "0123456789abcdef" for character in value
    ):
        _error(
            "invalid_sha256",
            "$.sha256",
            "policy hash must be lowercase SHA-256",
        )


def verify_signed_route_policy_bundle(bundle, public_keys, bundled_static_routes):
    if not isinstance(bundle, dict):
        _error("invalid_type", "$", "signed policy bundle must be an object")
    if not isinstance(public_keys, dict) or not public_keys:
        _error(
            "trusted_keys_required",
            "$.trusted_keys",
            "trusted policy keys are required",
        )

    _require_schema(bundle)

    if "key_id" not in bundle:
        _error("missing_field", "$.key_id", "key_id is required")
    key_id = bundle["key_id"]
    if not isinstance(key_id, str):
        _error("invalid_type", "$.key_id", "key_id must be a string")
    if key_id not in public_keys:
        _error("unknown_key", "$.key_id", "unknown policy key")

    if "signature" not in bundle:
        _error("missing_field", "$.signature", "signature is required")
    signature = bundle["signature"]
    if not isinstance(signature, str):
        _error(
            "invalid_type",
            "$.signature",
            "policy signature must be base64",
        )
    signature_bytes = _decode_base64(
        signature,
        path="$.signature",
        label="policy signature",
    )
    if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
        _error(
            "invalid_signature_length",
            "$.signature",
            "policy signature must be 64 bytes",
        )

    public_key_path = f"$.trusted_keys.{key_id}"
    public_key = public_keys[key_id]
    if not isinstance(public_key, str):
        _error(
            "invalid_type",
            public_key_path,
            "policy public key must be base64",
        )
    public_key_bytes = _decode_base64(
        public_key,
        path=public_key_path,
        label="policy public key",
    )
    if len(public_key_bytes) != ED25519_PUBLIC_KEY_LENGTH:
        _error(
            "invalid_public_key_length",
            public_key_path,
            "policy public key must be 32 bytes",
        )

    normalized = _normalize_manifest(bundle.get("manifest"), bundled_static_routes)
    canonical = _canonical_bytes_from_normalized(normalized)
    if "sha256" in bundle:
        expected_hash = bundle["sha256"]
        _validate_sha256(expected_hash)
        if expected_hash != hashlib.sha256(canonical).hexdigest():
            _error("hash_mismatch", "$.sha256", "policy hash mismatch")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        _error(
            "signature_support_unavailable",
            "$.signature",
            "policy signature support unavailable",
        )

    try:
        verifying_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError:
        _error(
            "invalid_public_key",
            public_key_path,
            "policy public key is invalid",
        )
    try:
        verifying_key.verify(signature_bytes, canonical)
    except InvalidSignature:
        _error(
            "signature_verification_failed",
            "$.signature",
            "policy signature verification failed",
        )
    return normalized
