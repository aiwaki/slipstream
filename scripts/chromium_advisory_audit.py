#!/usr/bin/env python3
"""Standalone candidate Chromium advisory evaluator, not a release gate.

This is NOT an OSV ecosystem alias or an absence-of-vulnerabilities assertion.
Unknown records/ranges and incomplete, stale or mismatched evidence cannot pass
this evaluator. Local inputs alone do not establish official source provenance.
The existing dependency audit remains authoritative for release acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import zipfile

CFT_URL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
CVE_RELEASE_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
RELEASE_FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates?alt=json&max-results=50"
CHROME_CNA = "ebfee0ef-53dd-4cf3-9e2a-08a5bd7a7e28"
VERSION = re.compile(r"\d+\.\d+\.\d+\.\d+")
PRIOR_BOUNDARY = re.compile(
    r"(?:Google Chrome|Chromium)(?: on(?: [A-Za-z ,/]+)?)? (?:prior to|before) "
    r"(\d+\.\d+\.\d+\.\d+|M\d+|\d+)(?!\d|\.\d)")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_AGE = timedelta(hours=24)
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024 * 1024
MAX_RECORD = 8 * 1024 * 1024
MAX_METADATA = 10 * 1024 * 1024


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def parse_json(raw: str | bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant {value}")
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def read_json(path: Path) -> dict:
    return parse_json(path.read_bytes())


def object_value(value, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"invalid {label} object")
    return value


def object_list(value, label: str) -> list[dict]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"invalid {label} list")
    return value


def version(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError("unknown Chromium version syntax")
    return tuple(map(int, value.split(".")))


def timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("invalid evidence timestamp") from exc
    if result.tzinfo is None:
        raise ValueError("evidence timestamp must include timezone")
    return result.astimezone(timezone.utc)


def not_future(when: datetime, now: datetime) -> None:
    if now.tzinfo is None or when > now + timedelta(minutes=5):
        raise ValueError("future evidence or missing evaluation timezone")


def fresh(when: datetime, now: datetime) -> None:
    not_future(when, now)
    if now - when > MAX_AGE:
        raise ValueError("stale evidence")


def bind_artifact(source: dict, cft: dict, now: datetime) -> dict:
    """Bind the genuine generic package to the exact CfT headless artifact."""
    version(source.get("version"))
    if source.get("platform") != "mac-arm64":
        raise ValueError("unreviewed headless platform")
    if source.get("component") != "Chrome for Testing chrome-headless-shell":
        raise ValueError("unexpected headless component")
    if source.get("license_path") != "LICENSE.headless_shell":
        raise ValueError("unexpected headless license")
    archive = object_value(source.get("archive"), "artifact archive")
    expected = ("https://storage.googleapis.com/chrome-for-testing-public/"
                f"{source['version']}/mac-arm64/chrome-headless-shell-mac-arm64.zip")
    if archive.get("url") != expected or not SHA256.fullmatch(str(archive.get("sha256", ""))):
        raise ValueError("invalid exact artifact provenance")
    if type(archive.get("length")) is not int or not 0 < archive["length"] <= MAX_ARCHIVE:
        raise ValueError("invalid artifact size")
    # This is the publication/update time of the current manifest, not our
    # acquisition time. A freshly fetched Stable version can be weeks old.
    not_future(timestamp(cft.get("timestamp")), now)
    stable = object_value(object_value(cft.get("channels"), "CfT channels").get("Stable"), "CfT stable")
    if stable.get("channel") != "Stable" or not isinstance(stable.get("revision"), str) or not stable["revision"].isdigit():
        raise ValueError("invalid CfT stable record")
    downloads = object_value(stable.get("downloads"), "CfT downloads")
    matches = [item for item in object_list(downloads.get("chrome-headless-shell"), "CfT headless downloads")
               if item.get("platform") == source["platform"]]
    if stable.get("version") != source["version"] or matches != [{"platform": "mac-arm64", "url": expected}]:
        raise ValueError("pin is not the exact current CfT stable headless artifact")
    return {"name": "chromium-headless-shell", "purl": f"pkg:generic/chromium-headless-shell@{source['version']}",
            "version": source["version"], "platform": source["platform"], "revision": stable["revision"],
            "archive": archive}


def bind_sbom(artifact: dict, packages: list[dict]) -> None:
    matches = [p for p in packages if p.get("name") == artifact["name"]]
    if len(matches) != 1:
        raise ValueError("expected one exact Chromium SBOM package")
    package = matches[0]
    purls = [p.get("referenceLocator") for p in package.get("externalRefs", []) if p.get("referenceType") == "purl"]
    hashes = [p.get("checksumValue") for p in package.get("checksums", []) if p.get("algorithm") == "SHA256"]
    if package.get("versionInfo") != artifact["version"] or purls != [artifact["purl"]] or hashes != [artifact["archive"]["sha256"]]:
        raise ValueError("Chromium SBOM identity does not match exact artifact")


def baseline_asset(release: dict, archive: Path, now: datetime) -> dict:
    tag = release.get("tag_name", "")
    match = re.fullmatch(r"cve_(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})Z", tag)
    if not match or release.get("draft") is not False or release.get("prerelease") is not False:
        raise ValueError("invalid official CVE baseline release")
    day = match[1]
    fresh(timestamp(day + "T00:00:00Z"), now)
    tag_time = timestamp(f"{day}T{match[2]}:{match[3]}:00Z")
    published = timestamp(release.get("published_at"))
    fresh(published, now)
    if published < tag_time or published.date() != tag_time.date():
        raise ValueError("inconsistent CVE baseline release timestamps")
    candidates = [a for a in object_list(release.get("assets"), "CVE release assets") if a.get("name") in (
        f"{day}_all_CVEs_at_midnight.zip", f"{day}_all_CVEs_at_midnight.zip.zip")]
    if len(candidates) != 1:
        raise ValueError("complete CVE baseline asset is missing or ambiguous")
    asset = candidates[0]
    url = f"https://github.com/CVEProject/cvelistV5/releases/download/{tag}/{asset['name']}"
    if asset.get("browser_download_url") != url or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(asset.get("digest", ""))):
        raise ValueError("unverified CVE baseline provenance")
    if type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_ARCHIVE:
        raise ValueError("invalid CVE baseline size")
    if archive.stat().st_size != asset["size"] or digest(archive) != asset["digest"][7:]:
        raise ValueError("CVE baseline archive integrity mismatch")
    return {"url": url, "sha256": asset["digest"][7:], "length": asset["size"], "as_of": day + "T00:00:00Z"}


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []
    def handle_data(self, value):
        self.parts.append(value)
    def handle_starttag(self, tag, attrs):
        if tag in {"p", "br", "div", "li", "h1", "h2", "h3", "tr"}:
            self.parts.append(" ")
    def handle_endtag(self, tag):
        self.handle_starttag(tag, [])


def release_cves(feed: dict, pinned_version: str, now: datetime) -> set[str]:
    """Check the latest desktop stable announcement for unpublished/missing CVEs."""
    data = object_value(feed.get("feed"), "Chrome Releases feed")
    if data.get("id", {}).get("$t") != "tag:blogger.com,1999:blog-8982037438137564684":
        raise ValueError("wrong Chrome Releases feed identity")
    not_future(timestamp(data.get("updated", {}).get("$t")), now)
    if data.get("openSearch$startIndex", {}).get("$t") != "1":
        raise ValueError("Chrome Releases feed does not start at latest entries")
    posts = [e for e in object_list(data.get("entry"), "Chrome Releases entries") if e.get("title", {}).get("$t") == "Stable Channel Update for Desktop"]
    if not posts:
        raise ValueError("latest desktop security announcement absent")
    post = max(posts, key=lambda e: timestamp(e.get("published", {}).get("$t")))
    not_future(timestamp(post.get("published", {}).get("$t")), now)
    links = [link.get("href", "") for link in object_list(post.get("link"), "Chrome Releases links")
             if link.get("rel") == "alternate" and link.get("type") == "text/html"]
    if len(links) != 1 or not re.fullmatch(r"https://chromereleases\.googleblog\.com/\d{4}/\d{2}/[A-Za-z0-9_-]+\.html", links[0]):
        raise ValueError("invalid desktop security announcement origin")
    parser = _Text(); parser.feed(post.get("content", {}).get("$t", ""))
    text = "".join(parser.parts)
    if not re.search(r"(?<![\d.])" + re.escape(pinned_version) + r"(?!\d|\.\d)", text):
        raise ValueError("latest desktop announcement does not match CfT version")
    counts = re.findall(r"(?:includes|contains)\s+(\d+)\s+security fixes", text, re.I)
    ids = set(CVE_ID.findall(text))
    if len(counts) != 1 or int(counts[0]) != len(ids) or not ids:
        raise ValueError("desktop security announcement has incomplete CVE inventory")
    return ids


def chromium_product(item: dict) -> bool:
    """Product identity, not a word match against extensions or other browsers."""
    name = str(item.get("product", "")).strip()
    return name.casefold() in {"chrome", "google chrome", "chromium", "chromium browser", "google chrome browser"} or bool(
        re.match(r"(?:Google Chrome|Chromium) (?:prior to|before) ", name))


def unspecified_product(item: dict) -> bool:
    return item.get("product") is None or str(item["product"]).strip().casefold() in {"", "n/a", "unspecified", "unknown"}


def supplemental_chromium_ranges(record: dict) -> bool:
    containers = object_value(record.get("containers"), "CVE containers")
    for adp in object_list(containers.get("adp", []), "CVE supplemental providers"):
        products = object_list(adp.get("affected", []), "ADP affected products")
        if any(chromium_product(item) for item in products):
            return True
    return False


def relevant(record: dict) -> bool:
    cna = object_value(object_value(record.get("containers"), "CVE containers").get("cna"), "CVE CNA")
    provider = object_value(cna.get("providerMetadata"), "CVE CNA provider")
    if supplemental_chromium_ranges(record):
        return True
    if record["cveMetadata"].get("assignerOrgId") == CHROME_CNA or provider.get("orgId") == CHROME_CNA:
        return True
    products = object_list(cna.get("affected"), "CVE affected products")
    if any(chromium_product(item) for item in products):
        return True
    # Legacy records with no product identity require review when they name
    # Chrome. A mention in an explicitly different product (for example a Chrome
    # extension or Firefox CVE) is not a Chromium affected-product assertion.
    return (not products or any(unspecified_product(item) for item in products)) and any(
        re.search(r"\b(?:Google Chrome|Chromium)\b", d.get("value", ""), re.I)
        for d in object_list(cna.get("descriptions"), "CVE descriptions"))


def evaluate_record_detail(record: dict, pinned_version: str) -> tuple[str, str]:
    """Evaluate only unambiguous vendor prior-to boundaries; everything else blocks.

    Chrome CNA custom versions often repeat the fixed version as both `version`
    and `lessThan`. We accept that convention ONLY when the CNA's English text
    explicitly says prior to/before the identical fixed version. No platform or
    headless reachability exemption is inferred from descriptions.
    """
    # No authority-precedence policy or ADP range interpreter has been reviewed
    # yet. A primary CNA boundary must not silently override a conflicting or
    # malformed supplemental Chromium range in the same official record.
    if supplemental_chromium_ranges(record):
        return "unknown", "supplemental-chromium-range-requires-review"
    cna = record.get("containers", {}).get("cna", {})
    english = " ".join(d.get("value", "") for d in object_list(cna.get("descriptions"), "CVE descriptions") if d.get("lang") == "en")
    boundary_matches = list(PRIOR_BOUNDARY.finditer(english))
    boundaries = {match[1] for match in boundary_matches}
    affected = cna.get("affected", [])
    if len(boundaries) != 1:
        return "unknown", "no-unique-explicit-chromium-fixed-boundary"
    all_boundaries = set(re.findall(r"(?:prior to|before)\s+(M?\d+(?:\.\d+)*)", english))
    if all_boundaries != boundaries or re.search(r"\b(?:all|later|subsequent|newer) versions\b|\band (?:later|newer)\b", english, re.I):
        return "unknown", "additional-or-open-ended-version-boundary"
    platform = r"(?:Linux|Windows|Mac|OS X|Android|ChromeOS)"
    suffix = rf"(?: (?:for|on) {platform}(?:,? (?:and )?{platform})*)?[, ]+(?:allowed|allows|allow)\b"
    if any(not re.match(suffix, english[match.end():]) for match in boundary_matches):
        return "unknown", "unsupported-fixed-boundary-clause"
    if not isinstance(affected, list) or not affected:
        return "unknown", "missing-affected-ranges"
    if not all(isinstance(item, dict) for item in affected):
        return "unknown", "malformed-affected-product"
    if any(not isinstance(item.get("product"), str) or not item["product"].strip() for item in affected):
        return "unknown", "missing-affected-product-identity"
    core_products = [item for item in affected if chromium_product(item)]
    if core_products:
        affected = core_products
    elif not all(unspecified_product(item) for item in affected):
        return "unknown", "component-advisory-without-chromium-product-range"
    fixed = next(iter(boundaries))
    normalized_fixed = fixed if VERSION.fullmatch(fixed) else fixed.removeprefix("M") + ".0.0.0"
    # Legacy prose may mention different Android/desktop thresholds after one
    # shared prefix. Do not silently apply the first threshold to every build.
    if set(VERSION.findall(english)) != ({fixed} if VERSION.fullmatch(fixed) else set()):
        return "unknown", "additional-component-or-platform-versions-in-description"
    for item in affected:
        if not isinstance(item, dict):
            return "unknown", "malformed-affected-product"
        ranges = item.get("versions", [])
        if not isinstance(ranges, list) or not ranges or item.get("defaultStatus") not in (None, "unaffected"):
            return "unknown", "missing-ranges-or-ambiguous-default-status"
        for entry in ranges:
            if not isinstance(entry, dict):
                return "unknown", "malformed-range"
            if set(entry) - {"version", "status", "lessThan", "versionType"}:
                return "unknown", "unsupported-range-fields"
            if entry.get("status") != "affected":
                return "unknown", "unsupported-range-status"
            if entry.get("lessThan") is not None:
                if entry.get("lessThan") != fixed or entry.get("version") not in (fixed, "0", "0.0.0.0", "unspecified") or entry.get("versionType") != "custom":
                    return "unknown", "structured-range-disagrees-with-fixed-boundary"
            elif entry.get("version") not in ("n/a", "unspecified", f"< {fixed}", f"before {fixed}", f"prior to {fixed}"):
                # Older official CNA records repeat a prior-to sentence in
                # version. Accept only that exact closed grammar, with the same
                # boundary already checked in the authoritative description.
                legacy = rf"(?:Google Chrome|Chromium) (?:prior to|before) {re.escape(fixed)}(?: (?:for|on) [A-Za-z ,/]+)?"
                if not isinstance(entry.get("version"), str) or not re.fullmatch(legacy, entry["version"]):
                    return "unknown", "unsupported-legacy-version-expression"
    return ("affected" if version(pinned_version) < version(normalized_fixed) else "not_affected"), "explicit-fixed-boundary:" + fixed


def evaluate_record(record: dict, pinned_version: str) -> str:
    return evaluate_record_detail(record, pinned_version)[0]


def _records(archive: zipfile.ZipFile):
    infos = archive.infolist()
    if len(infos) > 1_000_000 or sum(x.file_size for x in infos) > MAX_EXPANDED:
        raise ValueError("CVE archive exceeds resource bounds")
    names = set()
    for info in infos:
        path = PurePosixPath(info.filename)
        if info.filename in names or path.is_absolute() or ".." in path.parts or "\\" in info.filename:
            raise ValueError("duplicate or unsafe CVE archive entry")
        names.add(info.filename)
        if info.is_dir():
            continue
        # The official full baseline also includes synchronization metadata.
        # These are not records and must never substitute for the full corpus.
        if info.filename in ("cves/delta.json", "cves/deltaLog.json"):
            continue
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}\.json", path.name):
            raise ValueError("unexpected file in CVE record archive")
        if info.file_size > MAX_RECORD:
            raise ValueError("oversized CVE record")
        raw = archive.read(info)
        record = parse_json(raw)
        if not isinstance(record, dict) or record.get("dataType") != "CVE_RECORD" or record.get("dataVersion") not in ("5.0", "5.1", "5.1.1", "5.2"):
            raise ValueError("unsupported CVE record schema")
        metadata = object_value(record.get("cveMetadata"), "CVE metadata")
        if metadata.get("cveId") != path.stem or metadata.get("state") not in ("PUBLISHED", "REJECTED"):
            raise ValueError("invalid CVE record identity/state")
        yield record, hashlib.sha256(raw).hexdigest()


def scan_records(archive: Path, pinned_version: str) -> tuple[list[dict], int]:
    findings = []; seen = set(); count = 0
    def scan(z):
        nonlocal count
        for record, sha in _records(z):
            ident = record["cveMetadata"]["cveId"]
            if ident in seen:
                raise ValueError("duplicate CVE record identity")
            seen.add(ident); count += 1
            if record["cveMetadata"]["state"] == "REJECTED" or not relevant(record):
                continue
            status, reason = evaluate_record_detail(record, pinned_version)
            findings.append({"id": ident, "status": status, "reason": reason, "record_sha256": sha})
    with zipfile.ZipFile(archive) as outer:
        if outer.namelist() == ["cves.zip"]:
            info = outer.getinfo("cves.zip")
            if info.file_size > MAX_ARCHIVE:
                raise ValueError("nested CVE archive exceeds resource bound")
            with tempfile.TemporaryFile() as handle:
                with outer.open(info) as source:
                    shutil.copyfileobj(source, handle, 1024 * 1024)
                handle.seek(0)
                with zipfile.ZipFile(handle) as inner:
                    scan(inner)
        else:
            scan(outer)
    if not count or not findings:
        raise ValueError("empty CVE catalogue or Chromium advisory selection")
    return sorted(findings, key=lambda x: x["id"]), count


def audit(*, source: Path, cft: Path, release: Path, baseline: Path, feed: Path, now: datetime) -> dict:
    # Parse and hash the same immutable metadata bytes. Re-reading files after a
    # long catalogue scan could bind a decision to different evidence.
    raw = {key: path.read_bytes() for key, path in (("source", source), ("cft", cft), ("release", release), ("feed", feed))}
    artifact = bind_artifact(parse_json(raw["source"]), parse_json(raw["cft"]), now)
    snapshot = baseline_asset(parse_json(raw["release"]), baseline, now)
    required = release_cves(parse_json(raw["feed"]), artifact["version"], now)
    findings, total = scan_records(baseline, artifact["version"])
    if baseline.stat().st_size != snapshot["length"] or digest(baseline) != snapshot["sha256"]:
        raise ValueError("CVE baseline changed during evaluation")
    missing = sorted(required - {f["id"] for f in findings})
    unknown = sum(f["status"] == "unknown" for f in findings)
    affected = sum(f["status"] == "affected" for f in findings)
    return {"schema_version": 1, "generator": "slipstream-chromium-advisory-audit-1",
            "scope": "standalone-candidate-no-release-gate-integration",
            "evaluated_at": now.isoformat(), "artifact": artifact,
            "coverage": {"inventory": "supplied-full-baseline-shape-and-integrity-checked",
                         "selection": "chrome-cna-or-chromium-affected-product-or-ambiguous-legacy-identity",
                         "evaluation": "incomplete" if unknown or missing else "complete"},
            "limits": ["Public CVE snapshot only; embargoed and undiscovered issues are not covered.",
                       "No headless or platform reachability exemptions are inferred.",
                       "Embedded-component advisories without a Chrome/Chromium or Chrome-CNA mapping require a separate dependency inventory."],
            "expected_source_urls": {"cft": CFT_URL, "release": CVE_RELEASE_URL, "feed": RELEASE_FEED_URL},
            "provenance": "unverified-local-inputs",
            "inputs": {**{key + "_sha256": hashlib.sha256(value).hexdigest() for key, value in raw.items()}, "baseline": snapshot},
            "summary": {"catalogue_records": total, "chromium_records": len(findings), "affected": affected,
                        "unknown": unknown, "missing_release_cves": missing},
            "findings": findings, "evaluation_status": "fail" if affected or unknown or missing else "pass",
            "status": "fail"}


def _fetch_metadata(url: str) -> bytes:
    """Read only fixed primary metadata endpoints; never caller-selected URLs."""
    if url not in (CFT_URL, CVE_RELEASE_URL, RELEASE_FEED_URL):
        raise ValueError("unreviewed metadata endpoint")
    # curl is already required by repository build tooling. Its total deadline
    # also bounds a server that keeps trickling bytes just before socket timeout.
    with tempfile.TemporaryDirectory(prefix="chromium-advisory-fetch-") as tmp:
        body = Path(tmp) / "body.json"
        command = ["curl", "--disable", "--silent", "--show-error", "--fail", "--proto", "=https",
                   "--max-time", "30", "--max-filesize", str(MAX_METADATA), "--output", str(body),
                   "--write-out", "%{http_code}\n%{url_effective}", url]
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=35)
        except (subprocess.SubprocessError, OSError) as exc:
            raise ValueError("official metadata fetch did not complete within its bounds") from exc
        if result.stdout != f"200\n{url}":
            raise ValueError("metadata origin redirect or HTTP status mismatch")
        with body.open("rb") as stream:
            raw = stream.read(MAX_METADATA + 1)
        if len(raw) > MAX_METADATA:
            raise ValueError("metadata body size exceeds bound")
        parse_json(raw)
        return raw


def audit_from_official_metadata(*, source: Path, baseline: Path, evidence_dir: Path, now: datetime) -> dict:
    """Refresh primary metadata and authenticate the cached baseline by its digest.

    Offline verification of a retained report still needs a trusted CI/run
    attestation; a self-supplied JSON claim is not an origin proof.
    """
    evidence_dir.mkdir(parents=True, exist_ok=True)
    inputs = {}; origins = {}
    for key, url in (("cft", CFT_URL), ("release", CVE_RELEASE_URL), ("feed", RELEASE_FEED_URL)):
        raw = _fetch_metadata(url)
        path = evidence_dir / f"{key}.json"
        path.write_bytes(raw)
        inputs[key] = path
        origins[key] = {"url": url, "sha256": hashlib.sha256(raw).hexdigest()}
    report = audit(source=source, baseline=baseline, now=now, **inputs)
    if any(report["inputs"][key + "_sha256"] != origin["sha256"] for key, origin in origins.items()):
        raise ValueError("fetched official metadata changed before evaluation")
    report["provenance"] = "fresh-fixed-official-HTTPS-metadata"
    report["fetched_metadata"] = origins
    report["coverage"]["inventory"] = "official-full-published-cve-baseline"
    report["status"] = report["evaluation_status"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "baseline", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("cft", "release", "feed"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--refresh-official-metadata", type=Path, metavar="EVIDENCE_DIR")
    args = parser.parse_args()
    try:
        if args.refresh_official_metadata:
            if any((args.cft, args.release, args.feed)):
                raise ValueError("fresh official metadata cannot be mixed with supplied metadata")
            result = audit_from_official_metadata(source=args.source, baseline=args.baseline,
                         evidence_dir=args.refresh_official_metadata, now=datetime.now(timezone.utc))
        elif all((args.cft, args.release, args.feed)):
            result = audit(source=args.source, cft=args.cft, release=args.release, baseline=args.baseline,
                           feed=args.feed, now=datetime.now(timezone.utc))
        else:
            raise ValueError("provide all local metadata or refresh fixed official metadata")
    except (ValueError, OSError, KeyError, TypeError, AttributeError, zipfile.BadZipFile) as exc:
        result = {"status": "fail", "coverage": "incomplete", "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k in ("status", "summary", "error")}))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
