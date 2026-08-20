//! Fail-closed update-channel discovery shared by the tray and its tests.
//!
//! Stable builds use the configured Tauri `releases/latest` endpoint. Preview
//! builds must not move that stable pointer, so they discover the newest
//! immutable preview tag through a small, bounded GitHub Releases response and
//! then hand that tag-specific `latest.json` to Tauri's signed updater.

use base64::Engine;
use flate2::read::GzDecoder;
use minisign_verify::{PublicKey, Signature};
use reqwest::{redirect::Policy, Client, StatusCode};
use semver::Version;
use serde::Deserialize;
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::path::{Component, Path};
use std::time::Duration;
use tokio::time::Instant;

pub const REPOSITORY: &str = "aiwaki/slipstream";
pub const PREVIEW_RELEASES_API: &str =
    "https://api.github.com/repos/aiwaki/slipstream/releases?per_page=100";
pub const PREVIEW_RELEASES_PER_PAGE: usize = 100;
pub const MAX_PREVIEW_RELEASE_PAGES: usize = 3;
pub const MAX_RELEASES_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_RELEASES_TOTAL_BYTES: usize = MAX_RELEASES_RESPONSE_BYTES * MAX_PREVIEW_RELEASE_PAGES;
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
pub const DISCOVERY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const UPDATE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
pub const MAX_UPDATE_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_UPDATE_UNCOMPRESSED_BYTES: u64 = 768 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 4096;
pub const MAX_INFO_PLIST_BYTES: usize = 256 * 1024;
pub const BUNDLE_IDENTIFIER: &str = "dev.slipstream.tray";
pub const BUNDLE_EXECUTABLE: &str = "slipstream";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewRelease {
    pub version: Version,
    pub tag: String,
    pub appcast_url: String,
    pub archive_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub fn is_preview_version(version: &Version) -> bool {
    preview_sequence(version).is_some()
}

fn preview_sequence(version: &Version) -> Option<u64> {
    if !version.build.is_empty() {
        return None;
    }
    let mut parts = version.pre.as_str().split('.');
    if parts.next()? != "preview" {
        return None;
    }
    let sequence_text = parts.next()?;
    if parts.next().is_some()
        || sequence_text.is_empty()
        || (sequence_text.len() > 1 && sequence_text.starts_with('0'))
    {
        return None;
    }
    let sequence = sequence_text.parse::<u64>().ok()?;
    (sequence > 0).then_some(sequence)
}

fn parse_preview_tag(tag: &str) -> Option<Version> {
    let raw = tag.strip_prefix('v')?;
    let version = Version::parse(raw).ok()?;
    if preview_sequence(&version).is_none() || format!("v{version}") != tag {
        return None;
    }
    Some(version)
}

fn release_asset_url(tag: &str, asset: &str) -> String {
    format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{asset}")
}

pub fn select_preview_release(
    current: &Version,
    response: &[u8],
) -> Result<Option<PreviewRelease>, String> {
    if response.len() > MAX_RELEASES_RESPONSE_BYTES {
        return Err("preview release response exceeds the byte limit".into());
    }
    if !is_preview_version(current) {
        return Err("preview discovery requires a preview package version".into());
    }
    let releases: Vec<GithubRelease> = serde_json::from_slice(response)
        .map_err(|error| format!("invalid preview release response: {error}"))?;
    if releases.len() > PREVIEW_RELEASES_PER_PAGE {
        return Err("preview release response exceeds the item limit".into());
    }

    let mut selected: Option<PreviewRelease> = None;
    for release in releases {
        if release.draft || !release.prerelease {
            continue;
        }
        let Some(version) = parse_preview_tag(&release.tag_name) else {
            continue;
        };
        if version <= *current {
            continue;
        }
        let expected_appcast = release_asset_url(&release.tag_name, "latest.json");
        let expected_archive = release_asset_url(&release.tag_name, "Slipstream.app.tar.gz");
        let mut appcasts = release
            .assets
            .iter()
            .filter(|asset| asset.name == "latest.json");
        let Some(appcast) = appcasts.next() else {
            continue;
        };
        if appcasts.next().is_some() || appcast.browser_download_url != expected_appcast {
            continue;
        }
        let mut archives = release
            .assets
            .iter()
            .filter(|asset| asset.name == "Slipstream.app.tar.gz");
        let Some(archive) = archives.next() else {
            continue;
        };
        if archives.next().is_some() || archive.browser_download_url != expected_archive {
            continue;
        }
        let candidate = PreviewRelease {
            version,
            tag: release.tag_name,
            appcast_url: expected_appcast,
            archive_url: expected_archive,
        };
        if selected
            .as_ref()
            .is_none_or(|existing| candidate.version > existing.version)
        {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

pub async fn discover_preview_release(current: &Version) -> Result<Option<PreviewRelease>, String> {
    let client = Client::builder()
        .connect_timeout(DISCOVERY_CONNECT_TIMEOUT)
        .timeout(DISCOVERY_TIMEOUT)
        .redirect(Policy::none())
        .user_agent("Slipstream-Updater/1")
        .build()
        .map_err(|error| format!("preview discovery client unavailable: {error}"))?;
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    let mut selected: Option<PreviewRelease> = None;
    let mut total_bytes = 0_usize;
    for page in 1..=MAX_PREVIEW_RELEASE_PAGES {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "preview discovery exceeded its deadline".to_string())?;
        let mut response = client
            .get(format!("{PREVIEW_RELEASES_API}&page={page}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .timeout(remaining)
            .send()
            .await
            .map_err(|error| format!("preview discovery failed: {error}"))?;
        if response.status() != StatusCode::OK {
            return Err(format!(
                "preview discovery returned HTTP {}",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RELEASES_RESPONSE_BYTES as u64)
        {
            return Err("preview release response exceeds the byte limit".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("preview discovery body failed: {error}"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RELEASES_RESPONSE_BYTES
                || total_bytes
                    .saturating_add(body.len())
                    .saturating_add(chunk.len())
                    > MAX_RELEASES_TOTAL_BYTES
            {
                return Err("preview release response exceeds the byte limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        total_bytes = total_bytes.saturating_add(body.len());
        let item_count = serde_json::from_slice::<Vec<serde_json::Value>>(&body)
            .map_err(|error| format!("invalid preview release response: {error}"))?
            .len();
        if let Some(candidate) = select_preview_release(current, &body)? {
            if selected
                .as_ref()
                .is_none_or(|existing| candidate.version > existing.version)
            {
                selected = Some(candidate);
            }
        }
        if item_count < PREVIEW_RELEASES_PER_PAGE {
            return Ok(selected);
        }
    }
    Err("preview release history exceeds the bounded page limit".into())
}

pub fn decode_public_key(encoded: &str) -> Result<PublicKey, String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "updater public key is not valid base64".to_string())?;
    let text =
        std::str::from_utf8(&decoded).map_err(|_| "updater public key is not UTF-8".to_string())?;
    PublicKey::decode(text).map_err(|_| "updater public key is invalid".to_string())
}

pub fn decode_signature(encoded: &str) -> Result<Signature, String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "updater signature is not valid base64".to_string())?;
    let text =
        std::str::from_utf8(&decoded).map_err(|_| "updater signature is not UTF-8".to_string())?;
    Signature::decode(text).map_err(|_| "updater signature is invalid".to_string())
}

fn allowed_update_asset_url(url: &reqwest::Url, initial: bool) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    match url.host_str() {
        Some("github.com") => {
            if !initial {
                return true;
            }
            let Some(tag_and_asset) = url
                .path()
                .strip_prefix("/aiwaki/slipstream/releases/download/v")
            else {
                return false;
            };
            let Some(tag) = tag_and_asset.strip_suffix("/Slipstream.app.tar.gz") else {
                return false;
            };
            !tag.is_empty() && !tag.contains('/') && url.query().is_none()
        }
        Some("release-assets.githubusercontent.com") | Some("objects.githubusercontent.com") => {
            !initial
        }
        _ => false,
    }
}

fn allowed_update_redirect(next: &reqwest::Url, previous: &[reqwest::Url]) -> bool {
    previous.len() <= 3
        && allowed_update_asset_url(next, false)
        && !previous.iter().any(|url| url == next)
}

pub async fn download_verified_archive(
    url: &str,
    encoded_signature: &str,
    encoded_public_key: &str,
) -> Result<Vec<u8>, String> {
    let initial_url =
        reqwest::Url::parse(url).map_err(|_| "update archive URL is invalid".to_string())?;
    if !allowed_update_asset_url(&initial_url, true) {
        return Err("update archive URL is not an immutable GitHub asset".into());
    }
    let public_key = decode_public_key(encoded_public_key)?;
    let signature = decode_signature(encoded_signature)?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|_| "updater signature algorithm is unsupported".to_string())?;
    let redirect_policy = Policy::custom(|attempt| {
        if !allowed_update_redirect(attempt.url(), attempt.previous()) {
            attempt.error("unsafe update redirect")
        } else {
            attempt.follow()
        }
    });
    let client = Client::builder()
        .connect_timeout(DISCOVERY_CONNECT_TIMEOUT)
        .timeout(UPDATE_DOWNLOAD_TIMEOUT)
        .redirect(redirect_policy)
        .user_agent("Slipstream-Updater/1")
        .build()
        .map_err(|error| format!("update download client unavailable: {error}"))?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("update download failed: {error}"))?;
    if response.status() != StatusCode::OK {
        return Err(format!(
            "update download returned HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_UPDATE_ARCHIVE_BYTES as u64)
    {
        return Err("update archive exceeds the byte limit".into());
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .map(|length| length.min(MAX_UPDATE_ARCHIVE_BYTES as u64) as usize)
            .unwrap_or_default(),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("update download body failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_UPDATE_ARCHIVE_BYTES {
            return Err("update archive exceeds the byte limit".into());
        }
        verifier.update(&chunk);
        body.extend_from_slice(&chunk);
    }
    verifier
        .finalize()
        .map_err(|_| "update archive signature verification failed".to_string())?;
    Ok(body)
}

fn safe_archive_path(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn plist_string<'a>(dictionary: &'a plist::Dictionary, key: &str) -> Result<&'a str, String> {
    dictionary
        .get(key)
        .and_then(plist::Value::as_string)
        .ok_or_else(|| format!("update Info.plist is missing {key}"))
}

pub fn validate_macos_archive(archive: &[u8], expected_version: &Version) -> Result<(), String> {
    if archive.len() > MAX_UPDATE_ARCHIVE_BYTES {
        return Err("update archive exceeds the byte limit".into());
    }
    let decoder = GzDecoder::new(Cursor::new(archive));
    let mut tar = tar::Archive::new(decoder);
    let mut seen = HashSet::new();
    let mut info_plist = None;
    let mut executable_seen = false;
    let mut entries = 0usize;
    let mut total_uncompressed = 0u64;
    for entry in tar
        .entries()
        .map_err(|_| "update archive is not a readable tar.gz".to_string())?
    {
        entries = entries.saturating_add(1);
        if entries > MAX_ARCHIVE_ENTRIES {
            return Err("update archive exceeds the entry limit".into());
        }
        let mut entry = entry.map_err(|_| "update archive entry is invalid".to_string())?;
        let path = entry
            .path()
            .map_err(|_| "update archive path is invalid".to_string())?
            .into_owned();
        if !safe_archive_path(&path) || !seen.insert(path.clone()) {
            return Err("update archive has an unsafe or duplicate path".into());
        }
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir() || entry_type.is_symlink()) {
            return Err("update archive contains an unsupported entry type".into());
        }
        if entry_type.is_symlink() {
            let target = entry
                .link_name()
                .map_err(|_| "update symlink target is invalid".to_string())?
                .ok_or_else(|| "update symlink target is missing".to_string())?;
            if !safe_archive_path(&target) {
                return Err("update archive has an unsafe symlink target".into());
            }
        }
        total_uncompressed = total_uncompressed.saturating_add(entry.size());
        if entry.size() > MAX_ARCHIVE_ENTRY_BYTES {
            return Err("update archive entry exceeds the byte limit".into());
        }
        if total_uncompressed > MAX_UPDATE_UNCOMPRESSED_BYTES {
            return Err("update archive exceeds the uncompressed byte limit".into());
        }
        if path == Path::new("Slipstream.app/Contents/Info.plist") {
            if !entry_type.is_file() || entry.size() as usize > MAX_INFO_PLIST_BYTES {
                return Err("update Info.plist exceeds the byte limit".into());
            }
            let mut contents = Vec::with_capacity(entry.size() as usize);
            entry
                .read_to_end(&mut contents)
                .map_err(|_| "update Info.plist could not be read".to_string())?;
            info_plist = Some(contents);
        } else if path == Path::new("Slipstream.app/Contents/MacOS/slipstream") {
            let mode = entry
                .header()
                .mode()
                .map_err(|_| "update executable mode is invalid".to_string())?;
            executable_seen = entry_type.is_file() && mode & 0o111 != 0;
        } else if path
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            != Some("Slipstream.app")
        {
            return Err("update archive contains a second top-level entry".into());
        }
    }
    if !executable_seen {
        return Err("update archive is missing the Slipstream executable".into());
    }
    let plist = info_plist.ok_or_else(|| "update archive is missing Info.plist".to_string())?;
    let value = plist::Value::from_reader(Cursor::new(plist))
        .map_err(|_| "update Info.plist is invalid".to_string())?;
    let dictionary = value
        .as_dictionary()
        .ok_or_else(|| "update Info.plist is not a dictionary".to_string())?;
    if plist_string(dictionary, "CFBundleIdentifier")? != BUNDLE_IDENTIFIER {
        return Err("update bundle identifier mismatch".into());
    }
    if plist_string(dictionary, "CFBundleExecutable")? != BUNDLE_EXECUTABLE {
        return Err("update bundle executable mismatch".into());
    }
    let expected = expected_version.to_string();
    if plist_string(dictionary, "CFBundleShortVersionString")? != expected
        || plist_string(dictionary, "CFBundleVersion")? != expected
    {
        return Err("signed update archive version mismatch".into());
    }
    if dictionary
        .get("LSUIElement")
        .and_then(plist::Value::as_boolean)
        != Some(true)
    {
        return Err("signed update archive is not background-only".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        allowed_update_asset_url, allowed_update_redirect, is_preview_version,
        select_preview_release, validate_macos_archive, MAX_RELEASES_RESPONSE_BYTES,
        PREVIEW_RELEASES_PER_PAGE,
    };
    use flate2::{write::GzEncoder, Compression};
    use semver::Version;
    use serde_json::json;
    use tar::{Builder, EntryType, Header};

    fn release(tag: &str, prerelease: bool, draft: bool, asset_url: &str) -> serde_json::Value {
        json!({
            "tag_name": tag,
            "draft": draft,
            "prerelease": prerelease,
            "assets": [
                {"name": "latest.json", "browser_download_url": asset_url},
                {
                    "name": "Slipstream.app.tar.gz",
                    "browser_download_url": archive(tag)
                }
            ]
        })
    }

    fn appcast(tag: &str) -> String {
        format!("https://github.com/aiwaki/slipstream/releases/download/{tag}/latest.json")
    }

    fn archive(tag: &str) -> String {
        format!(
            "https://github.com/aiwaki/slipstream/releases/download/{tag}/Slipstream.app.tar.gz"
        )
    }

    fn append_file(builder: &mut Builder<GzEncoder<Vec<u8>>>, path: &str, data: &[u8], mode: u32) {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder.append_data(&mut header, path, data).unwrap();
    }

    fn update_archive(version: &str, executable_mode: u32) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut builder = Builder::new(encoder);
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.slipstream.tray</string>
<key>CFBundleExecutable</key><string>slipstream</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundleVersion</key><string>{version}</string>
<key>LSUIElement</key><true/>
</dict></plist>"#
        );
        append_file(
            &mut builder,
            "Slipstream.app/Contents/Info.plist",
            plist.as_bytes(),
            0o644,
        );
        append_file(
            &mut builder,
            "Slipstream.app/Contents/MacOS/slipstream",
            b"fixture",
            executable_mode,
        );
        builder.finish().unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn preview_version_shape_is_exact() {
        assert!(is_preview_version(
            &Version::parse("0.1.9-preview.23").unwrap()
        ));
        assert!(!is_preview_version(&Version::parse("0.1.9").unwrap()));
        assert!(!is_preview_version(
            &Version::parse("0.1.9-preview.0").unwrap()
        ));
        assert!(!is_preview_version(
            &Version::parse("0.1.9-beta.23").unwrap()
        ));
        assert!(!is_preview_version(
            &Version::parse("0.1.9-preview.23+local").unwrap()
        ));
    }

    #[test]
    fn archive_identity_and_version_are_bound_after_signature_verification() {
        let archive = update_archive("0.1.9-preview.24", 0o755);
        assert!(
            validate_macos_archive(&archive, &Version::parse("0.1.9-preview.24").unwrap()).is_ok()
        );
        assert_eq!(
            validate_macos_archive(&archive, &Version::parse("0.1.9-preview.25").unwrap())
                .unwrap_err(),
            "signed update archive version mismatch"
        );
        assert!(validate_macos_archive(
            &update_archive("0.1.9-preview.24", 0o644),
            &Version::parse("0.1.9-preview.24").unwrap()
        )
        .unwrap_err()
        .contains("executable"));
    }

    #[test]
    fn update_redirects_are_https_bounded_and_host_allowlisted() {
        let immutable = reqwest::Url::parse(
            "https://github.com/aiwaki/slipstream/releases/download/\
v0.1.9-preview.24/Slipstream.app.tar.gz",
        )
        .unwrap();
        let cdn = reqwest::Url::parse(
            "https://release-assets.githubusercontent.com/github-production-release-asset/1",
        )
        .unwrap();
        assert!(allowed_update_asset_url(&immutable, true));
        assert!(allowed_update_redirect(
            &cdn,
            std::slice::from_ref(&immutable)
        ));
        assert!(!allowed_update_asset_url(
            &reqwest::Url::parse(
                "https://github.com/aiwaki/slipstream/releases/latest/download/Slipstream.app.tar.gz"
            )
            .unwrap(),
            true
        ));
        assert!(!allowed_update_redirect(
            &reqwest::Url::parse("http://release-assets.githubusercontent.com/a").unwrap(),
            std::slice::from_ref(&immutable)
        ));
        assert!(!allowed_update_redirect(
            &reqwest::Url::parse("https://example.com/a").unwrap(),
            std::slice::from_ref(&immutable)
        ));
        assert!(!allowed_update_redirect(
            &immutable,
            std::slice::from_ref(&immutable)
        ));
        assert!(!allowed_update_redirect(
            &cdn,
            &[
                immutable.clone(),
                cdn.clone(),
                immutable.clone(),
                cdn.clone()
            ]
        ));
    }

    #[test]
    fn newest_semver_preview_with_exact_immutable_asset_wins() {
        let body = serde_json::to_vec(&json!([
            release(
                "v0.1.9-preview.24",
                true,
                false,
                &appcast("v0.1.9-preview.24")
            ),
            release(
                "v0.2.0-preview.1",
                true,
                false,
                &appcast("v0.2.0-preview.1")
            ),
            release(
                "v0.1.9-preview.99",
                true,
                true,
                &appcast("v0.1.9-preview.99")
            ),
            release("v0.2.0", false, false, &appcast("v0.2.0"))
        ]))
        .unwrap();
        let selected = select_preview_release(&Version::parse("0.1.9-preview.23").unwrap(), &body)
            .unwrap()
            .unwrap();

        assert_eq!(selected.version, Version::parse("0.2.0-preview.1").unwrap());
        assert_eq!(selected.tag, "v0.2.0-preview.1");
        assert_eq!(
            selected.archive_url,
            "https://github.com/aiwaki/slipstream/releases/download/\
v0.2.0-preview.1/Slipstream.app.tar.gz"
        );
    }

    #[test]
    fn mutable_or_cross_tag_appcast_is_rejected() {
        let body = serde_json::to_vec(&json!([
            release(
                "v0.1.9-preview.24",
                true,
                false,
                "https://github.com/aiwaki/slipstream/releases/latest/download/latest.json"
            ),
            release(
                "v0.1.9-preview.25",
                true,
                false,
                &appcast("v0.1.9-preview.24")
            )
        ]))
        .unwrap();
        assert_eq!(
            select_preview_release(&Version::parse("0.1.9-preview.23").unwrap(), &body).unwrap(),
            None
        );
    }

    #[test]
    fn missing_duplicate_or_cross_tag_archive_is_rejected() {
        let mut missing = release(
            "v0.1.9-preview.24",
            true,
            false,
            &appcast("v0.1.9-preview.24"),
        );
        missing["assets"].as_array_mut().unwrap().pop();

        let mut duplicate = release(
            "v0.1.9-preview.25",
            true,
            false,
            &appcast("v0.1.9-preview.25"),
        );
        duplicate["assets"].as_array_mut().unwrap().push(json!({
            "name": "Slipstream.app.tar.gz",
            "browser_download_url": archive("v0.1.9-preview.25")
        }));

        let mut cross_tag = release(
            "v0.1.9-preview.26",
            true,
            false,
            &appcast("v0.1.9-preview.26"),
        );
        cross_tag["assets"][1]["browser_download_url"] = json!(archive("v0.1.9-preview.25"));

        let body = serde_json::to_vec(&json!([missing, duplicate, cross_tag])).unwrap();
        assert_eq!(
            select_preview_release(&Version::parse("0.1.9-preview.23").unwrap(), &body).unwrap(),
            None
        );
    }

    #[test]
    fn current_version_is_a_noop() {
        let body = serde_json::to_vec(&json!([release(
            "v0.1.9-preview.23",
            true,
            false,
            &appcast("v0.1.9-preview.23")
        )]))
        .unwrap();
        assert_eq!(
            select_preview_release(&Version::parse("0.1.9-preview.23").unwrap(), &body).unwrap(),
            None
        );
    }

    #[test]
    fn response_bounds_and_channel_are_fail_closed() {
        assert!(select_preview_release(
            &Version::parse("0.1.9-preview.23").unwrap(),
            &vec![b' '; MAX_RELEASES_RESPONSE_BYTES + 1]
        )
        .unwrap_err()
        .contains("byte limit"));
        assert!(
            select_preview_release(&Version::parse("0.1.9").unwrap(), b"[]")
                .unwrap_err()
                .contains("requires a preview")
        );

        let too_many = serde_json::to_vec(&vec![
            json!({
                "tag_name": "invalid",
                "draft": false,
                "prerelease": true,
                "assets": []
            });
            PREVIEW_RELEASES_PER_PAGE + 1
        ])
        .unwrap();
        assert!(
            select_preview_release(&Version::parse("0.1.9-preview.23").unwrap(), &too_many)
                .unwrap_err()
                .contains("item limit")
        );
    }
}
