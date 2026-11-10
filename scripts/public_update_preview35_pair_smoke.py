#!/usr/bin/env python3
"""Normal published .34 tray -> published .35 on an isolated hosted macOS runner.

This exercises real background discovery, AXPress and the app's own privileged
preparation. It never invokes a prepare hook, changes the candidate or supplies
a custom endpoint. A disposable administrator fixture exercises the real dialog.
Unknown outcomes are retained for runner disposal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

from build_packaged_update_trigger import pins
from native_root_update import Native, Refused, bounded_output, digest, document, guard, modules, require
from packaged_update_observer import exact_equal, same_process
from public_update_preview35_menu_smoke import PublicMenu, VERSION, require_public_feed
from public_update_observer import PublicObserver, PublicPreAckObserver
from qualify_packaged_update_commit import cleanup_committed, install_old, prerequisite
from stop_quit_ui_smoke import fixture_admin


NEW_SOURCE = '5a3e64b534affc865826fbd20ac67f1af328629e'
PAIR = {'schema_version': 1,
 'old': {'source_commit': 'a0a60e080cc97214cebd7491f4ea5d56dff66e0e',
         'candidate_manifest_sha256': 'e71e6ea85e821c836fdd363af1989d4cac237a47586dd45c1f7a78dcc09f9deb',
         'run_id': 41634434348,
         'run_attempt': 1},
 'new': {'source_commit': '5a3e64b534affc865826fbd20ac67f1af328629e',
         'candidate_manifest_sha256': '65748e547a3f36abaf728fa310a41e83e53a743daf708755028d39f8fb18014d',
         'run_id': 42874103966,
         'run_attempt': 2}}
PUBLIC_RELEASES = {'old': {'version': '0.1.9-preview.34',
         'release_id': 433775703,
         'release_name': 'Slipstream 0.1.9-preview.34 (архивная)',
         'tauri_config_sha256': '6cfee75f192ca05507d3c29b3e548874929ddfe18bfa6691e98dc6bcce66d220',
         'assets': {'artifact-manifest.json': [709085510,
                                               3107,
                                               '623951cea53dc5926911c8c1ed43f4b9fd048a4dbcdcf201b581e53a10512435'],
                    'dependency-audit.json': [709085552,
                                              39908,
                                              'fdc2e5b52a450207325d13f575c0a05ef75ff4df96f31ab334ff72675fdcdf77'],
                    'latest.json': [709085506,
                                    704,
                                    '8b08c54e0e7d37f54f92e31969ee7129e03d19cba1eb6d3631da2764d3cb3e96'],
                    'release-candidate-manifest.json': [709085513,
                                                        1988,
                                                        'e71e6ea85e821c836fdd363af1989d4cac237a47586dd45c1f7a78dcc09f9deb'],
                    'release-qualification.json': [709085511,
                                                   563,
                                                   'a7c9113160b83654059dae091f4e4127237b60fa13aadcbd4f0ef49a993438f5'],
                    'release-readiness.json': [709085617,
                                               1233,
                                               'f87b87194e1a23664d3cd082c1bcc0d68451e0df760c3e8b5bfb721e45d2e0b3'],
                    'Slipstream-macos-arm64.zip': [709085542,
                                                   149727266,
                                                   '4fcaec9b2619db431d5627a3537f0fd62b2bba1875710087eb46287c5a0cf4a4'],
                    'Slipstream.app.tar.gz': [709085565,
                                              153658305,
                                              '443caaf7c83f170e3baa73577f15018616e0a88a023ba3c46be77037501e7b04'],
                    'Slipstream.app.tar.gz.sig': [709085566,
                                                  408,
                                                  'a571d8d07529a347769f418a7b505c8f57a2969e25a13f274f38694873413431'],
                    'Slipstream.spdx.json': [709085541,
                                             350441,
                                             '09c44a5763de870da8e9baa78818a5e5544705cfb017bcb21147b60f4051b9f7'],
                    'Slipstream_0.1.9-preview.34_aarch64.dmg': [709085519,
                                                                150318678,
                                                                '5be0db23a8d6682ac3b30e00b7b19fa40be3e84efd1b4b69dee15125140972ea'],
                    'transport-mechanics.json': [709085514,
                                                 2944,
                                                 '610a8f0b642aee3a259e871a9533fefd09e274b4db49a6f5abfb1a0109555832']}},
 'new': {'version': '0.1.9-preview.35',
         'release_id': 440846924,
         'release_name': 'Slipstream 0.1.9-preview.35',
         'tauri_config_sha256': 'de676b3cdc73a466d1564373d5d41469af37d6dbe206fd7597d06ea026f6be2a',
         'assets': {'artifact-manifest.json': [732769223,
                                               3107,
                                               'd5577f4f95522fb709e9de8fab3a26c5a02255416ed3fb85a629d52e94b11542'],
                    'dependency-audit.json': [732769226,
                                              39908,
                                              'b039c0e24d18aa6e444fab4927f5f5ffad3204d7831b0172a1ffac9aa19d4383'],
                    'latest.json': [732769213,
                                    704,
                                    '430721cd66f37519dc84758e9b50ba8620542433a5a541017f19a22acb375430'],
                    'release-candidate-manifest.json': [732769220,
                                                        1988,
                                                        '65748e547a3f36abaf728fa310a41e83e53a743daf708755028d39f8fb18014d'],
                    'release-qualification.json': [732769225,
                                                   563,
                                                   '21d97a975ac2b2be2d0c758c45fecaa3ca0757c09d10c594f47c937e6bd74d64'],
                    'release-readiness.json': [732769224,
                                               1233,
                                               '8c5ad63e0ed657ee7e6a1cf991c116bcf1ccf86c14274bf663106172422ff328'],
                    'Slipstream-macos-arm64.zip': [732769218,
                                                   149821249,
                                                   '550a553ef9d8bcfcf9b7c0b53a906f05be9ca8e362bb3ed4960ae67a72ca3942'],
                    'Slipstream.app.tar.gz': [732769227,
                                              153749487,
                                              '427504013cecdfe128ea2b215e35f690857681a1654bd386742dd0d826c9731c'],
                    'Slipstream.app.tar.gz.sig': [732769219,
                                                  408,
                                                  'da3031526d0f6459b299a98bef322de3ff31149213d2765265142ed3bb9c0656'],
                    'Slipstream.spdx.json': [732769221,
                                             350441,
                                             '1d74396073dbcae6abbf908216daa51c67e2e5082836f7ccde96ac506ecba0db'],
                    'Slipstream_0.1.9-preview.35_aarch64.dmg': [732769232,
                                                                150410160,
                                                                '54a68e2e3302e696d381d41fc0ba43b70a2830f7478ff4083ca1ea0caa50d115'],
                    'transport-mechanics.json': [732769217,
                                                 2944,
                                                 '85e5b01c1a60a5490dfcdb2764664e5bfa53b11f1af4647156f147b552b1acd5']}}}
ROOT_GATE = (42887546582, 1)
REUSED = ("native_root_update.py", "packaged_update_observer.py", "packaged_update_preack.py",
          "qualify_packaged_update_commit.py", "build_packaged_update_trigger.py", "verify_packaged_observer_source.py",
          "stop_quit_ui_smoke.py", "geph_owned_lifecycle_smoke.py")


def require_public_pins():
    """Require complete release pins before any CLI, filesystem or network work."""
    require(type(ROOT_GATE[0]) is int and ROOT_GATE[0] > 0 and ROOT_GATE[1] == 1,
            "PENDING accepted root gate")
    for side in ("old", "new"):
        spec = PUBLIC_RELEASES[side]
        require(type(spec["release_id"]) is int and spec["release_id"] > 0,
                "PENDING published release ID: " + side)
        require(type(spec["release_name"]) is str and spec["release_name"].startswith("Slipstream ")
                and "PENDING" not in spec["release_name"], "PENDING published release title: " + side)
        require(len(spec["assets"]) == 12, "reviewed public asset inventory required")
        for name, (asset_id, size, sha) in spec["assets"].items():
            require(type(asset_id) is int and asset_id > 0 and type(size) is int and size > 0
                    and isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha),
                    "PENDING published asset identity: " + name)


def source_binding(backend):
    qualified = backend.args.repo
    require(VERSION == PUBLIC_RELEASES["new"]["version"], "menu target differs from pinned public release")
    require(os.environ.get("GITHUB_REPOSITORY") == "aiwaki/slipstream"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_REF") == "refs/heads/main", "main workflow dispatch required")
    harness = Path(__file__).resolve().parents[1]
    def git(root, *args):
        return backend.run(["/usr/bin/git", "-C", root, *args]).stdout
    require(git(qualified, "rev-parse", "HEAD").decode().strip() == NEW_SOURCE
            and not git(qualified, "status", "--porcelain", "--untracked-files=no"), "qualified product source changed")
    harness_sha = git(harness, "rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[a-f0-9]{40}", harness_sha) and harness_sha == os.environ.get("GITHUB_SHA")
            and not git(harness, "status", "--porcelain", "--untracked-files=no"), "harness source changed")
    hashes = {}
    for name in REUSED:
        relative = "scripts/" + name
        expected = hashlib.sha256(git(qualified, "show", NEW_SOURCE + ":" + relative)).hexdigest()
        require(digest(qualified / relative) == expected and digest(harness / relative) == expected,
                "shared qualification helper differs from qualified source: " + name)
        hashes[relative] = expected
    public = ("public_update_ax.py", "public_update_ui_preflight.py", "public_update_preview35_menu_smoke.py",
              "public_update_observer.py", "public_update_preview35_pair_smoke.py", "public_update_visibility.py")
    for name in public:
        relative = "scripts/" + name
        expected = hashlib.sha256(git(harness, "show", harness_sha + ":" + relative)).hexdigest()
        require(digest(harness / relative) == expected, "public harness bytes changed")
        hashes[relative] = expected
    return {"harness_source": harness_sha, "qualified_product_source": NEW_SOURCE, "sha256": hashes}


def validate_public_inventory(metadata, side, directory):
    """Freeze the reviewed public release inventory, including API artifact identity."""
    spec = PUBLIC_RELEASES[side]
    rows = metadata.get("assets")
    require(isinstance(rows, list) and len(rows) == len(spec["assets"]), "public asset count changed")
    by_name = {}
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("name"), str)
                and row["name"] not in by_name, "invalid/duplicate public asset")
        by_name[row["name"]] = row
    require(set(by_name) == set(spec["assets"]), "public asset inventory changed")
    base = f"https://github.com/aiwaki/slipstream/releases/download/v{spec['version']}/"
    for name, (asset_id, size, sha) in spec["assets"].items():
        row = by_name[name]
        require(type(row.get("id")) is int and row["id"] == asset_id
                and type(row.get("size")) is int and row["size"] == size
                and row.get("digest") == "sha256:" + sha and row.get("state") == "uploaded"
                and row.get("browser_download_url") == base + name,
                "public asset identity changed: " + name)
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == size
                and digest(path) == sha, "public asset bytes changed: " + name)


def run_public_validator(backend, command, *, public, kind, final=False, timeout=90):
    """Retain bounded diagnostics only for the two fixed public-file validators."""
    scripts = {"publication": "verify_published_release.py", "updater-signature": "verify_updater_artifacts.py"}
    require(kind in scripts and len(command) >= 2 and command[0] == sys.executable
            and Path(command[1]) == backend.args.repo / "scripts" / scripts[kind],
            "diagnostics require a fixed public validator")
    environment = {key: value for key, value in backend.env.items()
                   if key in {"HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "PATH"}}
    response = backend.run(command, timeout=timeout, check=False, env=environment)
    if response.returncode != 0:
        report = {"schema_version": 1, "validator": kind, "phase": "final" if final else "initial",
                  "returncode": response.returncode, "stderr": bounded_output(response.stderr, limit=4096),
                  "stdout_omitted": True}
        path = public / (kind + (".final" if final else "") + "-failure.json")
        with path.open("x") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        raise Refused(kind + " validator failed; bounded diagnostic retained")
    return json.loads(response.stdout)


def verify_public_side(backend, side, *, final=False):
    args, spec = backend.args, PUBLIC_RELEASES[side]
    require(args.repository == "aiwaki/slipstream", "fixed public repository required")
    public = args.public_root / side
    assets = public / "assets"
    metadata = public / ("release.final.json" if final else "release.json")
    tag = public / ("tag.final.json" if final else "tag.json")
    validate_public_inventory(document(metadata), side, assets)
    command = [sys.executable, args.repo / "scripts/verify_published_release.py",
        "--release-metadata", metadata, "--tag-ref", tag, "--release-dir", assets,
        "--repository", args.repository, "--version", spec["version"], "--tag", "v" + spec["version"],
        "--channel", "preview", "--release-name", spec["release_name"],
        "--source-commit", PAIR[side]["source_commit"], "--target", "aarch64-apple-darwin",
        "--release-id", str(spec["release_id"]), "--state", "published"]
    verified = run_public_validator(backend, command, public=public, kind="publication", final=final)
    config = public / "tauri.conf.json"
    require(digest(config) == spec["tauri_config_sha256"], "source-bound updater config changed")
    signature = run_public_validator(backend, [sys.executable, args.repo / "scripts/verify_updater_artifacts.py",
        "--release-dir", assets, "--version", spec["version"], "--tauri-config", config],
        public=public, kind="updater-signature", final=final, timeout=120)
    appcast = document(assets / "latest.json")
    platform = appcast.get("platforms", {}).get("darwin-aarch64", {})
    base = f"https://github.com/{args.repository}/releases/download/v{spec['version']}/"
    require(appcast.get("version") == spec["version"] and platform.get("url") == base + "Slipstream.app.tar.gz"
            and platform.get("signature") == (assets / "Slipstream.app.tar.gz.sig").read_text().strip(),
            "public appcast endpoint/signature mismatch")
    return {"release": verified, "updater_signature": signature,
            "public_release_metadata_sha256": digest(metadata), "public_tag_ref_sha256": digest(tag),
            "appcast_sha256": digest(assets / "latest.json"), "endpoint": base + "latest.json",
            "archive_url": platform["url"], "archive_sha256": digest(assets / "Slipstream.app.tar.gz"),
            "origin": "published release", "endpoint_network_capture": False}


def candidate_names(directory):
    manifest = document(directory / "release-candidate-manifest.json")
    names = ["release-candidate-manifest.json"] + [item["name"] for item in manifest["artifacts"]]
    require(len(names) == 7 and len(set(names)) == 7
            and all(isinstance(name, str) and Path(name).name == name for name in names),
            "candidate inventory changed")
    return names


def public_binding(backend):
    results = {}
    for side in ("old", "new"):
        results[side] = verify_public_side(backend, side)
        candidate = getattr(backend.args, side + "_candidate_dir")
        assets = backend.args.public_root / side / "assets"
        names = candidate_names(candidate)
        require({p.name for p in candidate.iterdir()} == set(names), "candidate contains non-candidate release assets")
        for name in names:
            require(digest(candidate / name) == digest(assets / name),
                    side.upper() + " candidate is not the published payload: " + name)
    return results


def refresh_public_metadata(backend):
    """Retain a fresh public identity snapshot after the real UI transaction."""
    results = {}
    for side, spec in PUBLIC_RELEASES.items():
        public = backend.args.public_root / side
        for filename, endpoint in (("release.final.json", "releases/tags/v" + spec["version"]),
                                   ("tag.final.json", "git/ref/tags/v" + spec["version"])):
            data = backend.run([backend.args.gh, "api", f"repos/{backend.args.repository}/{endpoint}"], github=True).stdout
            with (public / filename).open("xb") as stream:
                stream.write(data)
        results[side] = verify_public_side(backend, side, final=True)
    return results


def prepare_public(backend, pair_root):
    """Download public assets only; materialize_pair authenticates the subset before extraction.

    The historical OLD policy is intentionally not reinterpreted by today's
    verify_release_artifacts default. Native.verified_manifest binds its own policy.
    """
    args = backend.args
    require(args.repository == "aiwaki/slipstream", "fixed public repository required")
    for side in ("old", "new"):
        spec = PUBLIC_RELEASES[side]
        public = args.public_root / side
        public.mkdir(mode=0o700)
        for filename, endpoint in (("release.json", "releases/tags/v" + spec["version"]),
                                   ("tag.json", "git/ref/tags/v" + spec["version"])):
            data = backend.run([args.gh, "api", f"repos/{args.repository}/{endpoint}"], github=True).stdout
            with (public / filename).open("xb") as stream:
                stream.write(data)
        config = backend.run([args.gh, "api", "-H", "Accept: application/vnd.github.raw+json",
            f"repos/{args.repository}/contents/app-tauri/src-tauri/tauri.conf.json?ref={PAIR[side]['source_commit']}"],
            github=True).stdout
        with (public / "tauri.conf.json").open("xb") as stream:
            stream.write(config)
        backend.run([sys.executable, args.repo / "scripts/download_github_release_assets.py",
            "--repo", args.repository, "--tag", "v" + spec["version"], "--output", public / "assets",
            "--pattern", "*"], timeout=240, github=True,
            env={**backend.env, "PATH": str(Path(args.gh).parent) + os.pathsep + backend.env["PATH"]})
        # The canonical publication verifier requires the local notes projection
        # alongside the 12 public assets. It is not another downloadable asset.
        body = document(public / "release.json").get("body")
        require(isinstance(body, str), "published release notes body is unavailable")
        with (public / "assets" / "release-notes.md").open("x", encoding="utf-8") as stream:
            stream.write(body + "\n")
        proof = verify_public_side(backend, side)
        with (public / "verification.json").open("x") as stream:
            json.dump(proof, stream, indent=2, sort_keys=True)
        candidate = pair_root / (side + "-candidate")
        candidate.mkdir(mode=0o700)
        for name in candidate_names(public / "assets"):
            shutil.copyfile(public / "assets" / name, candidate / name)


def prepare_main(argv):
    require_public_pins()
    parser = argparse.ArgumentParser(description="Verify both immutable published releases before native extraction")
    for name in ("repo", "root", "public-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--gh", required=True)
    args = parser.parse_args(argv)
    uid = guard()
    os.umask(0o077)
    args.repository = "aiwaki/slipstream"
    args.repo = args.repo.resolve(strict=True)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    for name in ("root", "public_root"):
        path = getattr(args, name)
        require(path.parent.resolve(strict=True) == temp and not os.path.lexists(path),
                "fresh direct RUNNER_TEMP directory required")
        path = temp / path.name
        setattr(args, name, path)
        path.mkdir(mode=0o700)
    tproxy, candidate = modules(args.repo)
    backend = Native(args, uid, tproxy, candidate)
    source_binding(backend)
    prepare_public(backend, args.root)
    return 0


def cleanup_before_click(backend):
    require(not backend.click_attempted and backend.identity is None, "pending public action prevents cleanup")
    if backend.old_launch_attempted:
        require(hasattr(backend, "original_process") and backend.initiator is not None,
                "OLD launch outcome unknown; runner disposal required")
        child = backend.original_process
        if child.poll() is None:
            require(same_process(backend.initiator, backend.process_snapshot(child.pid))
                    and digest(backend.target / "Contents/MacOS/slipstream") == backend.expected["old"]["app_executable_sha256"],
                    "pre-click cleanup OLD identity changed")
            child.terminate()  # Owned fixture cleanup, never the qualified OLD update exit.
            child.wait(timeout=10)
        require(backend.process_snapshot(child.pid) is None, "OLD process remains/reused before cleanup")
    Native.teardown(backend)


def drive(backend):
    from public_update_visibility import PublicUpdateVisibility
    require_public_feed(backend)
    install_old(backend)
    backend.menu = PublicMenu(backend)
    backend.visibility = PublicUpdateVisibility()
    backend.visibility.start()
    backend.visibility.set_phase("discovery")
    backend.menu.launch()
    backend.menu.discover()
    # Metadata authentication has finished. Neither the ordinary app nor native
    # authorization helpers inherit a GitHub credential during the actual test.
    tokens = {key: os.environ.pop(key) for key in ("GH_TOKEN", "GITHUB_TOKEN") if key in os.environ}
    cancelled = None
    try:
        with fixture_admin() as (username, password):
            backend.visibility.set_phase("interaction")
            if backend.args.mode == "commit":
                backend.configure_authorization(username, password, mode="cancel")
                backend.menu.press()
                cancelled = backend.wait_cancelled()
                require(cancelled.get("native_cancel_qualified") is True,
                        "native Cancel did not prove an unchanged OLD installation")
                backend.menu.finish_click()
                backend.reset_after_cancel()  # Refuses any unproven/unfinished operation.
                backend.menu.discover()  # Refreshed offer or ordinary Check; never rewrite app state.
            backend.configure_authorization(username, password, mode="confirm")
            backend.menu.press()
            qualified = backend.qualify_app()
            backend.transaction_observed = True
            backend.menu.finish_click()
            require(backend.authorization_confirmed is True, "native administrator interaction not observed")
    finally:
        os.environ.update(tokens)
    backend.visibility.set_phase("terminal")
    require(backend.original_exited, "original normal app exit was not observed")
    return {**qualified, "public_update_transaction_qualified": True, "normal_old_update_exit_qualified": True,
            "public_discovery_qualified": True, "production_authorization_completed": True,
            "administrator_dialog_interaction_qualified": True, "native_cancel": cancelled,
            "normal_quit_qualified": False, "notification_delivery_qualified": False, "public_pair_qualified": False}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "pair-manifest", "old-candidate-dir", "new-candidate-dir", "old-app", "new-app",
                 "root-gate-dir", "public-root", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--root-gate-run-id", type=int, required=True)
    parser.add_argument("--root-gate-attempt", type=int, required=True)
    parser.add_argument("--gh", required=True)
    parser.add_argument("--repository", default="aiwaki/slipstream")
    parser.add_argument("--mode", choices=("commit", "kill-successor-before-ack"), default="commit")
    return parser.parse_args(argv)


def main(argv=None):
    require_public_pins()
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "prepare-public":
        return prepare_main(argv[1:])
    args = parse_args(argv)
    uid = guard()
    os.umask(0o077)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    for name in ("repo", "pair_manifest", "old_candidate_dir", "new_candidate_dir", "old_app", "new_app",
                 "root_gate_dir", "public_root"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.output_dir = args.output_dir.absolute()
    require(args.output_dir.parent == temp and not os.path.lexists(args.output_dir), "new direct RUNNER_TEMP output required")
    require((args.root_gate_run_id, args.root_gate_attempt) == ROOT_GATE, "fixed root prerequisite required")
    args.output_dir.mkdir(mode=0o700)
    args.output = args.output_dir / "public-update-result.json"
    tproxy, candidate = modules(args.repo)
    backend = (PublicObserver if args.mode == "commit" else PublicPreAckObserver)(args, uid, tproxy, candidate)
    backend.old_launch_attempted = backend.click_attempted = backend.transaction_observed = False
    backend.visibility = None
    result = {"schema_version": 2, "status": "failed", "mode": args.mode,
              "public_pair_qualified": False, "public_update_transaction_qualified": False,
              "transaction_observed": False, "cleanup_errors": [],
              "not_qualified": ["notification delivery/removal",
                                "normal Quit", "browser routing", "other updater fault windows"]}
    with args.output.open("x") as stream:
        try:
            pair = pins(document(args.pair_manifest))
            require(exact_equal(pair, PAIR), "public qualification pair differs from pinned .34 -> .35")
            result["source_binding"] = source_binding(backend)
            for side in ("old", "new"):
                backend.expected[side] = backend.artifact(side, pair[side], getattr(args, side + "_app"),
                                                           getattr(args, side + "_candidate_dir"))
            result["public_release"] = public_binding(backend)
            metadata = json.loads(backend.run([args.gh, "api",
                f"repos/{args.repository}/actions/runs/{args.root_gate_run_id}/attempts/{args.root_gate_attempt}"], github=True).stdout)
            result["root_prerequisite"] = prerequisite(metadata, args.root_gate_dir, pair, backend.expected,
                                                       args.root_gate_run_id, args.root_gate_attempt)
            require(exact_equal(result["source_binding"], source_binding(backend)), "source changed before installation")
            result.update(drive(backend), status="passed")
            result["public_release_final"] = refresh_public_metadata(backend)
        except Exception as error:
            result.update(error_type=type(error).__name__, reason=str(error)[:512], status="failed")
        finally:
            if backend.visibility is not None:
                try:
                    result["visibility"] = backend.visibility.close()
                    backend.visibility.assert_passed()
                except Exception as error:
                    result.update(status="failed", visibility_error=str(error)[:512])
            try:
                if backend.transaction_observed:
                    cleanup_committed(backend) if args.mode == "commit" else backend.cleanup_rollback()
                elif backend.click_attempted:
                    backend.retain_public_diagnostic()
                    raise Refused("public action outcome incomplete; pending privilege/transaction retained for runner disposal")
                else:
                    cleanup_before_click(backend)
            except Exception as error:
                result["cleanup_errors"].append(str(error)[:512])
                result["status"] = "failed"
            if hasattr(backend, "menu"):
                backend.menu.close()
            result.update(events=backend.events, identity=backend.identity, transaction_observed=backend.transaction_observed)
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
