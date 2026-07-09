#!/usr/bin/env python3
"""Build a signed Slipstream route-policy bundle for release hosting."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPIKE = ROOT / "spike"
if str(SPIKE) not in sys.path:
    sys.path.insert(0, str(SPIKE))

import tproxy  # noqa: E402


def _load_private_key(private_key: str):
    try:
        raw = base64.b64decode(private_key.strip(), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("private key must be base64") from exc
    if len(raw) != 32:
        raise ValueError("private key must be a raw Ed25519 private key")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise ValueError("policy signature support unavailable") from exc
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_key_b64(private_key) -> str:
    from cryptography.hazmat.primitives import serialization

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_key).decode("ascii")


def build_signed_route_policy_bundle(
    *,
    manifest: dict,
    key_id: str,
    private_key: str,
) -> tuple[dict, dict[str, str]]:
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("key id is required")
    key_id = key_id.strip()
    normalized = tproxy.validate_route_policy_manifest(manifest)
    signing_key = _load_private_key(private_key)
    signature = signing_key.sign(tproxy.route_policy_canonical_bytes(normalized))
    bundle = {
        "schema": tproxy.ROUTE_POLICY_SCHEMA_VERSION,
        "key_id": key_id,
        "sha256": tproxy.route_policy_hash(normalized),
        "manifest": normalized,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    public_keys = {key_id: _public_key_b64(signing_key)}
    tproxy.verify_signed_route_policy_bundle(bundle, public_keys)
    return bundle, public_keys


def verify_signed_route_policy_bundle_file(
    *,
    bundle_path: Path,
    public_keys_path: Path,
) -> dict:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    public_keys = tproxy.load_trusted_route_policy_keys(
        path=str(public_keys_path),
        embedded_keys={},
    )
    manifest = tproxy.verify_signed_route_policy_bundle(bundle, public_keys)
    return {
        "source": manifest["source"],
        "sha256": tproxy.route_policy_hash(manifest),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--bundled-manifest", action="store_true")
    parser.add_argument("--key-id")
    parser.add_argument("--private-key-file", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--public-keys-output", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--public-keys", type=Path)
    args = parser.parse_args(argv)
    if args.verify:
        if not args.bundle or not args.public_keys:
            parser.error("--verify requires --bundle and --public-keys")
        return args
    if args.bundled_manifest == bool(args.manifest):
        parser.error("choose exactly one of --manifest or --bundled-manifest")
    if not args.key_id:
        parser.error("--key-id is required")
    if not args.private_key_file:
        parser.error("--private-key-file is required")
    if not args.output:
        parser.error("--output is required")
    return args


def _read_manifest(args: argparse.Namespace) -> dict:
    if args.bundled_manifest:
        return tproxy.route_policy_manifest()
    return json.loads(args.manifest.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.verify:
        verify_signed_route_policy_bundle_file(
            bundle_path=args.bundle,
            public_keys_path=args.public_keys,
        )
        return 0
    manifest = _read_manifest(args)
    private_key = args.private_key_file.read_text(encoding="utf-8")
    bundle, public_keys = build_signed_route_policy_bundle(
        manifest=manifest,
        key_id=args.key_id,
        private_key=private_key,
    )
    _write_json(args.output, bundle)
    if args.public_keys_output:
        _write_json(args.public_keys_output, {"keys": public_keys})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
