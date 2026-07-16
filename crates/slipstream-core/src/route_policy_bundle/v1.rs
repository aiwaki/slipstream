use crate::route_policy_manifest::{
    parse_route_policy_manifest, ManifestRoutePolicy, RoutePolicyManifest,
    RoutePolicyManifestError, RoutePolicyManifestErrorCode,
};
use crate::routing_policy::{RouteClass, StrategySet};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

pub const ROUTE_POLICY_BUNDLE_CONTRACT_VERSION: u32 = 1;

const SCHEMA_VERSION: i128 = 1;
const SHA256_HEX_LENGTH: usize = 64;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePolicyBundleErrorCode {
    InvalidJson,
    InvalidType,
    MissingField,
    OutOfRange,
    TrustedKeysRequired,
    UnknownKey,
    InvalidBase64,
    InvalidPublicKeyLength,
    InvalidPublicKey,
    InvalidSignatureLength,
    InvalidSha256,
    HashMismatch,
    SignatureVerificationFailed,
    ManifestInvalid,
}

impl RoutePolicyBundleErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::InvalidType => "invalid_type",
            Self::MissingField => "missing_field",
            Self::OutOfRange => "out_of_range",
            Self::TrustedKeysRequired => "trusted_keys_required",
            Self::UnknownKey => "unknown_key",
            Self::InvalidBase64 => "invalid_base64",
            Self::InvalidPublicKeyLength => "invalid_public_key_length",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::InvalidSignatureLength => "invalid_signature_length",
            Self::InvalidSha256 => "invalid_sha256",
            Self::HashMismatch => "hash_mismatch",
            Self::SignatureVerificationFailed => "signature_verification_failed",
            Self::ManifestInvalid => "manifest_invalid",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoutePolicyBundleError {
    pub code: RoutePolicyBundleErrorCode,
    pub path: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_error_code: Option<RoutePolicyManifestErrorCode>,
}

impl RoutePolicyBundleError {
    fn new(
        code: RoutePolicyBundleErrorCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
            manifest_error_code: None,
        }
    }

    fn from_manifest(error: RoutePolicyManifestError) -> Self {
        let suffix = error.path.strip_prefix('$').unwrap_or(&error.path);
        Self {
            code: RoutePolicyBundleErrorCode::ManifestInvalid,
            path: format!("$.manifest{suffix}"),
            message: error.message,
            manifest_error_code: Some(error.code),
        }
    }
}

impl fmt::Display for RoutePolicyBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at {}", self.message, self.path)
    }
}

impl std::error::Error for RoutePolicyBundleError {}

pub fn route_policy_canonical_bytes(manifest: &RoutePolicyManifest) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("{\"attempt_limits\":{");
    for (index, (route, limit)) in manifest.attempt_limits.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, route);
        write!(&mut output, ":{limit}").expect("writing to String cannot fail");
    }
    output.push_str("},\"geo_exit_routes\":");
    push_routes(&mut output, &manifest.geo_exit_routes);
    output.push_str(",\"source\":");
    push_json_string(&mut output, &manifest.source);
    output.push_str(",\"static_routes\":");
    push_routes(&mut output, &manifest.static_routes);
    write!(&mut output, ",\"version\":{}}}", manifest.version)
        .expect("writing to String cannot fail");
    output.into_bytes()
}

pub fn route_policy_hash(manifest: &RoutePolicyManifest) -> String {
    let digest = Sha256::digest(route_policy_canonical_bytes(manifest));
    format!("{digest:x}")
}

pub fn verify_signed_route_policy_bundle_json(
    raw: &str,
    trusted_keys: &BTreeMap<String, String>,
) -> Result<RoutePolicyManifest, RoutePolicyBundleError> {
    let value: Value = serde_json::from_str(raw).map_err(|error| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidJson,
            "$",
            format!("signed policy bundle is not valid JSON: {error}"),
        )
    })?;
    verify_signed_route_policy_bundle(&value, trusted_keys)
}

pub fn verify_signed_route_policy_bundle(
    bundle: &Value,
    trusted_keys: &BTreeMap<String, String>,
) -> Result<RoutePolicyManifest, RoutePolicyBundleError> {
    let root = bundle.as_object().ok_or_else(|| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidType,
            "$",
            "signed policy bundle must be an object",
        )
    })?;
    if trusted_keys.is_empty() {
        return Err(RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::TrustedKeysRequired,
            "$.trusted_keys",
            "trusted policy keys are required",
        ));
    }

    require_schema(root.get("schema"))?;

    let key_id = require_string(root.get("key_id"), "$.key_id", "key_id")?;
    let encoded_public_key = trusted_keys.get(key_id).ok_or_else(|| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::UnknownKey,
            "$.key_id",
            "unknown policy key",
        )
    })?;
    let public_key_path = format!("$.trusted_keys.{key_id}");

    let encoded_signature =
        require_string(root.get("signature"), "$.signature", "policy signature")?;
    let signature_bytes = decode_base64(encoded_signature, "$.signature", "policy signature")?;
    if signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
        return Err(RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidSignatureLength,
            "$.signature",
            "policy signature must be 64 bytes",
        ));
    }

    let public_key_bytes =
        decode_base64(encoded_public_key, &public_key_path, "policy public key")?;
    if public_key_bytes.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidPublicKeyLength,
            &public_key_path,
            "policy public key must be 32 bytes",
        ));
    }
    let public_key_array: [u8; ED25519_PUBLIC_KEY_LENGTH] = public_key_bytes
        .try_into()
        .expect("public key length was checked");
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|_| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidPublicKey,
            &public_key_path,
            "policy public key is invalid",
        )
    })?;

    let manifest = parse_route_policy_manifest(root.get("manifest").unwrap_or(&Value::Null))
        .map_err(RoutePolicyBundleError::from_manifest)?;
    let canonical = route_policy_canonical_bytes(&manifest);

    if let Some(expected_hash) = root.get("sha256") {
        let expected_hash = expected_hash.as_str().ok_or_else(|| {
            RoutePolicyBundleError::new(
                RoutePolicyBundleErrorCode::InvalidType,
                "$.sha256",
                "policy hash must be a string",
            )
        })?;
        if !is_lowercase_sha256(expected_hash) {
            return Err(RoutePolicyBundleError::new(
                RoutePolicyBundleErrorCode::InvalidSha256,
                "$.sha256",
                "policy hash must be lowercase SHA-256",
            ));
        }
        if expected_hash != route_policy_hash(&manifest) {
            return Err(RoutePolicyBundleError::new(
                RoutePolicyBundleErrorCode::HashMismatch,
                "$.sha256",
                "policy hash mismatch",
            ));
        }
    }

    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidSignatureLength,
            "$.signature",
            "policy signature must be 64 bytes",
        )
    })?;
    verifying_key
        .verify_strict(&canonical, &signature)
        .map_err(|_| {
            RoutePolicyBundleError::new(
                RoutePolicyBundleErrorCode::SignatureVerificationFailed,
                "$.signature",
                "policy signature verification failed",
            )
        })?;
    Ok(manifest)
}

fn require_schema(value: Option<&Value>) -> Result<(), RoutePolicyBundleError> {
    let value = value.ok_or_else(|| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::MissingField,
            "$.schema",
            "schema is required",
        )
    })?;
    let integer = if let Some(signed) = value.as_i64() {
        signed as i128
    } else if let Some(unsigned) = value.as_u64() {
        unsigned as i128
    } else {
        return Err(RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidType,
            "$.schema",
            "schema must be an integer",
        ));
    };
    if integer != SCHEMA_VERSION {
        return Err(RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::OutOfRange,
            "$.schema",
            "unsupported policy bundle schema",
        ));
    }
    Ok(())
}

fn require_string<'a>(
    value: Option<&'a Value>,
    path: &str,
    label: &str,
) -> Result<&'a str, RoutePolicyBundleError> {
    let value = value.ok_or_else(|| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::MissingField,
            path,
            format!("{} is required", path.rsplit('.').next().unwrap_or(label)),
        )
    })?;
    value.as_str().ok_or_else(|| {
        let message = if path == "$.signature" {
            "policy signature must be base64".to_owned()
        } else {
            format!("{label} must be a string")
        };
        RoutePolicyBundleError::new(RoutePolicyBundleErrorCode::InvalidType, path, message)
    })
}

fn decode_base64(
    encoded: &str,
    path: &str,
    label: &str,
) -> Result<Vec<u8>, RoutePolicyBundleError> {
    STANDARD.decode(encoded).map_err(|_| {
        RoutePolicyBundleError::new(
            RoutePolicyBundleErrorCode::InvalidBase64,
            path,
            format!("{label} is not valid base64"),
        )
    })
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn push_routes(output: &mut String, routes: &[ManifestRoutePolicy]) {
    output.push('[');
    for (index, route) in routes.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"domains\":[");
        for (domain_index, domain) in route.domains.iter().enumerate() {
            if domain_index > 0 {
                output.push(',');
            }
            push_json_string(output, domain);
        }
        output.push_str("],\"route_class\":");
        push_json_string(output, route_class_name(route.route_class));
        output.push_str(",\"service_group\":");
        push_json_string(output, route.service_group.as_str());
        output.push_str(",\"strategy_set\":");
        push_json_string(output, strategy_set_name(route.strategy_set));
        output.push('}');
    }
    output.push(']');
}

fn route_class_name(route_class: RouteClass) -> &'static str {
    match route_class {
        RouteClass::DirectPassthrough => "direct_passthrough",
        RouteClass::DirectFirst => "direct_first",
        RouteClass::LocalBypass => "local_bypass",
        RouteClass::GeoExit => "geo_exit",
        RouteClass::Unknown => "unknown",
    }
}

fn strategy_set_name(strategy_set: StrategySet) -> &'static str {
    match strategy_set {
        StrategySet::Direct => "direct",
        StrategySet::DirectFirst => "direct_first",
        StrategySet::FakeOnly => "fake_only",
        StrategySet::Geph => "geph",
        StrategySet::General => "general",
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if ('\u{00}'..='\u{1f}').contains(&character) => {
                write!(output, "\\u{:04x}", character as u32)
                    .expect("writing to String cannot fail");
            }
            character if (character as u32) <= 0x7e => output.push(character),
            character if (character as u32) <= 0xffff => {
                write!(output, "\\u{:04x}", character as u32)
                    .expect("writing to String cannot fail");
            }
            character => {
                let scalar = character as u32 - 0x1_0000;
                let high = 0xd800 + (scalar >> 10);
                let low = 0xdc00 + (scalar & 0x3ff);
                write!(output, "\\u{high:04x}\\u{low:04x}").expect("writing to String cannot fail");
            }
        }
    }
    output.push('"');
}
