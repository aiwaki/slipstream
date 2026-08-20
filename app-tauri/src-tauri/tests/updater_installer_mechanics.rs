#![cfg(target_os = "macos")]

use base64::Engine;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use tauri::test::{mock_builder, mock_context, noop_assets};
use tauri_plugin_updater::UpdaterExt;
use tempfile::TempDir;

const CURRENT_VERSION: &str = "0.1.9-preview.23";
const UPDATE_VERSION: &str = "0.1.9-preview.24";
const TEST_PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDY5RTE3MTU1ODNBMDU3Q0IKUldUTFY2Q0RWWEhoYVV1K1l3aGtGdFBxeDZYVllYcDZwZjhPWlFoK0JsbnhGT05lTTJadVI3MHYK";
const TEST_SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVUTFY2Q0RWWEhoYVFqb1FnQXAwWndzWnRoci82L2RrNit2MVE4NWp5cFBwcVI1NXVnUkZTQzM3L0NvQWIrUG5vVFBsYlVKRVBONEpXMTJyWEdNbENpVUxWRStEYnZ0SVE0PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzg2NjMzNzA4CWZpbGU6Zml4dHVyZTI0LnRhci5negpUTTUrUGFTLzh1eGc4bU9qOUNRcXpZMk01NEZKSWU4OTNUV2hyT09GM2d3NldGOVA2TGhnd05DaTlLbWs2eGVJK0h2TmZaMlczdG1NZVlEUFgxNDhCZz09Cg==";
const TEST_ARCHIVE_BASE64: &str = "H4sIAAAAAAAAA+1XXW/aMBRle+RXuJkmnoidLzuZgIpSukZiK1top0p9SRO3RA1JlJiPaq/74TO0XQQsIAZlEvV5sZLY9147PufYXXdyTl2fptAJgyRjKXUHspskpR0CIUQMA8xajGctx0uLkKogoBiqRjQDY10HSMEq0UpgsssiijDMmJvyUtxg7D4Exf3GfUrDFXHmJwV2XeZrQUNgwIIBrSvExFjTsIZl07I0jAlRywYBHfuk+b11bl+15YnLWCp78WyDhFRO0nhEIzfyaL35zW72z068i88+cX54Zd0CDh/UuV416N370q/ujXn/074v/+91eKuYZz18lRzr+D99mOe/riPOf+NVqlnAG+f/wv/v/rGDVhwxGrFsBzk21n+Vd0RC//eBAv3HJtEsIvT/4LHA/xfW79QINtd/zBVA6P8+UPT/cyP44noXzlY51uo/Igv6ryBd6P9eoFp/1X/d1HRTyP/ho4j/M9bvyAU213+i6KrQ/31gvf7b0V0sJ2GQsX/Nwddj+ls3OP+riqIK/d8HCs7/REOKaQkDOHgU8X971udYx3+Ml+7//LEE0Pap1+ON8792PBmEYETTLIijuqTISAI08mI/iO7r0mXvrGpKx41y7ej0otW77rbBbE+A7uVJx24BqQphc0prCE97p6DbsZ0e4DEgbH+VgNRnLPkE4Xg8fiY/l4FpR24vaZzQlD12eLAqHyD7zJd4mqfoc+Xwt37gsUYZgNoDfWy0zk6GkR9S2+cbNbgLaFqD0/fT73wn87obPh3JWb6xWeo+1uDzt8UwTj9O2dVTQmfWZSkckhXZqiYpHQV0LKt6Yaz2hHpD5t6GdClGXs7S6I5zabdDOuDTyYexdEghnzp8mnsNzlamsXOdXH3+y08Bef2b59jk/kdUwvmvqaoh/H8fWLr/mUQmmkosfgYT9n/4WM3/bVifY+39z9AW+K+ohib8fx/4cARvgwhm/XLCTYndgcrH7CaqgMqi6VUERwUEBAQOCb8B6Zc29QAmAAA=";

struct FixtureServer {
    endpoint: String,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.join().expect("fixture HTTP server failed");
        }
    }
}

fn respond(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn fixture_server(version: &str, signature: &str, expected_requests: usize) -> FixtureServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = format!("http://{address}/latest.json");
    let archive_url = format!("http://{address}/Slipstream.app.tar.gz");
    let archive = base64::engine::general_purpose::STANDARD
        .decode(TEST_ARCHIVE_BASE64)
        .unwrap();
    let appcast = serde_json::to_vec(&json!({
        "version": version,
        "platforms": {
            "darwin-aarch64": {
                "signature": signature,
                "url": archive_url
            }
        }
    }))
    .unwrap();
    let join = thread::spawn(move || {
        for _ in 0..expected_requests {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let count = stream.read(&mut request).unwrap();
            let first_line = String::from_utf8_lossy(&request[..count])
                .lines()
                .next()
                .unwrap_or_default()
                .to_string();
            if first_line.contains(" /latest.json ") {
                respond(stream, "200 OK", "application/json", &appcast);
            } else if first_line.contains(" /Slipstream.app.tar.gz ") {
                respond(stream, "200 OK", "application/octet-stream", &archive);
            } else {
                respond(stream, "404 Not Found", "text/plain", b"not found");
            }
        }
    });
    FixtureServer {
        endpoint,
        join: Some(join),
    }
}

fn tampered_signature() -> String {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(TEST_SIGNATURE)
        .unwrap();
    let text = String::from_utf8(decoded).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let replacement = if lines[1].as_bytes()[20] == b'A' {
        "B"
    } else {
        "A"
    };
    lines[1].replace_range(20..21, replacement);
    let tampered = format!("{}\n", lines.join("\n"));
    base64::engine::general_purpose::STANDARD.encode(tampered)
}

fn temporary_app() -> (TempDir, PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("slipstream-updater-e2e-")
        .tempdir()
        .unwrap();
    let app = root.path().join("Slipstream.app");
    let executable = app.join("Contents/MacOS/slipstream");
    fs::create_dir_all(executable.parent().unwrap()).unwrap();
    fs::write(&executable, b"#!/bin/sh\nprintf '%s\\n' 'current'\n").unwrap();
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).unwrap();
    (root, executable)
}

fn test_app(endpoint: &str) -> tauri::App<tauri::test::MockRuntime> {
    let mut context = mock_context(noop_assets());
    context.package_info_mut().version = CURRENT_VERSION.parse().unwrap();
    context.config_mut().plugins.0.insert(
        "updater".into(),
        json!({
            "dangerousInsecureTransportProtocol": true,
            "endpoints": [endpoint],
            "pubkey": TEST_PUBLIC_KEY
        }),
    );
    mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(context)
        .unwrap()
}

async fn checked_update(
    app: &tauri::App<tauri::test::MockRuntime>,
    executable: &Path,
) -> Option<tauri_plugin_updater::Update> {
    app.handle()
        .updater_builder()
        .executable_path(executable)
        .build()
        .unwrap()
        .check()
        .await
        .unwrap()
}

#[tokio::test]
async fn mock_runtime_signed_installer_replaces_a_disposable_app() {
    let server = fixture_server(UPDATE_VERSION, TEST_SIGNATURE, 2);
    let (root, executable) = temporary_app();
    let app = test_app(&server.endpoint);
    let update = checked_update(&app, &executable).await.unwrap();

    update.download_and_install(|_, _| {}, || {}).await.unwrap();
    // Executing the fixture only proves replacement bytes are runnable. This
    // mechanics test does not claim to exercise Tauri app.restart(), a packaged
    // Slipstream bundle, native notification delivery, or successor health.
    let output = std::process::Command::new(&executable).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        UPDATE_VERSION
    );
    let plist = fs::read_to_string(root.path().join("Slipstream.app/Contents/Info.plist")).unwrap();
    assert!(plist.contains("<key>LSUIElement</key>"));
    assert!(plist.contains("<string>0.1.9-preview.24</string>"));
}

#[tokio::test]
async fn current_version_is_a_network_noop() {
    let server = fixture_server(CURRENT_VERSION, TEST_SIGNATURE, 1);
    let (_root, executable) = temporary_app();
    let app = test_app(&server.endpoint);

    assert!(checked_update(&app, &executable).await.is_none());
    assert!(fs::read_to_string(&executable).unwrap().contains("current"));
}

#[tokio::test]
async fn tampered_signature_fails_before_replacing_the_app() {
    let signature = tampered_signature();
    let server = fixture_server(UPDATE_VERSION, &signature, 2);
    let (_root, executable) = temporary_app();
    let app = test_app(&server.endpoint);
    let update = checked_update(&app, &executable).await.unwrap();

    assert!(update.download_and_install(|_, _| {}, || {}).await.is_err());
    assert!(fs::read_to_string(&executable).unwrap().contains("current"));
}
