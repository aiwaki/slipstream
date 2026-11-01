#!/usr/bin/env python3
"""Normal published .32 tray -> published .33 on an isolated hosted macOS runner.

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
from public_update_preview33_menu_smoke import PublicMenu, VERSION, require_public_feed
from public_update_observer import PublicObserver, PublicPreAckObserver
from qualify_packaged_update_commit import cleanup_committed, install_old, prerequisite
from stop_quit_ui_smoke import fixture_admin


NEW_SOURCE = '9eccd1ddf691aef5f76d493103513f2fada2fd5c'
PAIR = {'schema_version': 1,
 'old': {'source_commit': 'fd7d43c271e4a46ac2d10fc5ca4a032b92adae73',
         'run_id': 41164190639,
         'run_attempt': 1,
         'candidate_manifest_sha256': '3ddfb32e6b7ab1d2101ca96feba173bd30d3883eb5bc5a1204896d93f518e823'},
 'new': {'source_commit': '9eccd1ddf691aef5f76d493103513f2fada2fd5c',
         'candidate_manifest_sha256': 'e2e0e5432ea12208922c775c7a6d7ea5ab87f44491d45de94524df8c41193ba0',
         'run_id': 41302269258,
         'run_attempt': 1}}
PUBLIC_RELEASES = {'old': {'version': '0.1.9-preview.32',
         'release_id': 429722639,
         'release_name': 'Slipstream 0.1.9-preview.32 (архивная)',
         'tauri_config_sha256': '1f1fec117833b18bb163648b7b48c7459c67178797be95fc167d55da4d665bd0',
         'assets': {'artifact-manifest.json': [694364526,
                                               3107,
                                               '4d55b151f08864b9001c670430e6c927d58fa4bcf96f9a3883fbadc272774775'],
                    'dependency-audit.json': [694364521,
                                              39364,
                                              'ff253460b80da93837e641f3af8768f94eb0dc56ee0b174f5a9148a7e642fd9e'],
                    'latest.json': [694364519,
                                    704,
                                    'cb8762ed8aca08e89d8b3dbb955f0f89cf831c64946347185bfcf43c7bd413f2'],
                    'release-candidate-manifest.json': [694364525,
                                                        1988,
                                                        '3ddfb32e6b7ab1d2101ca96feba173bd30d3883eb5bc5a1204896d93f518e823'],
                    'release-qualification.json': [694364520,
                                                   563,
                                                   '22b857c01d55f0ab5895d2eb562368c2efc1750201e230adc32857b58fc03872'],
                    'release-readiness.json': [694364518,
                                               1233,
                                               '03ab727282d6e5f001bba5635cad8a70ac33d1262359ab74e678bbf6c66fd154'],
                    'Slipstream-macos-arm64.zip': [694364516,
                                                   148926546,
                                                   '54fb843cdc31e1bd363d71ac363e55c292336b81d20707e1474b223810192468'],
                    'Slipstream.app.tar.gz': [694364515,
                                              152863067,
                                              '5fa28933c68541bb876cbba9abb59c6331121d53d60c7481243b0810665024f9'],
                    'Slipstream.app.tar.gz.sig': [694364514,
                                                  408,
                                                  '096aa6aa76dca4a7d7e9a0b7b7142fd53006c0c8c8aae1532e185e0381e447db'],
                    'Slipstream.spdx.json': [694364523,
                                             345936,
                                             '6b4f88628e4e4990b578467b60d53a86171850f6e7b3cad7cd06b04411e449b5'],
                    'Slipstream_0.1.9-preview.32_aarch64.dmg': [694364527,
                                                                149508237,
                                                                'e9b07ebc09eca99d14b27064b66762021ab57e458fffb750edfdc5ad678b34b7'],
                    'transport-mechanics.json': [694364517,
                                                 2944,
                                                 'ecd755500745fa99f8e8a03800fc0f8f61e23e2e1b6f2b281ca48eac0d50d538']}},
 'new': {'version': '0.1.9-preview.33',
         'release_id': 430591253,
         'release_name': 'Slipstream 0.1.9-preview.33',
         'tauri_config_sha256': 'f41a5a64023e21d53fab1783179403d435c0bcd949a1904c92d994a8d62c8eb5',
         'assets': {'artifact-manifest.json': [698372793,
                                               3107,
                                               'b682582bb290f4db8e267f78828afae91b03a4fcd7e35c722adab4b8fe280a3a'],
                    'dependency-audit.json': [698372799,
                                              39908,
                                              'e89315f27fbc5e9be1a8fefdd97e2958b4844c08c52312782b39bc4339e95464'],
                    'latest.json': [698372797,
                                    704,
                                    'aa3cf4395aeb79e2d115db4f3a6a4f90dad0c9ff1f410b92873747d8aa372a3a'],
                    'release-candidate-manifest.json': [698372806,
                                                        1988,
                                                        'e2e0e5432ea12208922c775c7a6d7ea5ab87f44491d45de94524df8c41193ba0'],
                    'release-qualification.json': [698372791,
                                                   563,
                                                   '6787d267edd1961a0ac3480fda05373718e7f92fe67b3b66e37e2a9e4f834591'],
                    'release-readiness.json': [698372805,
                                               1232,
                                               'de650703209c5e0eadca1d3a1ef8b43409e3921bf1ef9cb5a79f0d963204bca6'],
                    'Slipstream-macos-arm64.zip': [698372798,
                                                   149726030,
                                                   'f279e42be86f6ba196d743bec269035d733178b5ad1d68ba8937f659ee18842b'],
                    'Slipstream.app.tar.gz': [698372790,
                                              153657487,
                                              'c9c93e38781cb62eb2316b6e3606dbbea9c6c6f10a35b0ac5c68b02deed93465'],
                    'Slipstream.app.tar.gz.sig': [698372796,
                                                  408,
                                                  '18c7db4af03fb2d292387619086056d694fe37c036cef78e39f6197a6b0fa07f'],
                    'Slipstream.spdx.json': [698372792,
                                             350441,
                                             '8bf490ec0efaff9e4ee4d3d1b621eb70576e3d5a8ca5abbb690a5e00b08be2c9'],
                    'Slipstream_0.1.9-preview.33_aarch64.dmg': [698372802,
                                                                150319335,
                                                                '714be64c192662ace7236729a1469f980777eb104b75a46c44d118661b028a61'],
                    'transport-mechanics.json': [698372804,
                                                 2944,
                                                 'ae3f0c1c30bfc479753ac7e3fbd2f6fceae29be34d9706fb56bcd6fc811e714c']}}}
ROOT_GATE = (41303686569, 1)
REUSED = ("native_root_update.py", "packaged_update_observer.py", "packaged_update_preack.py",
          "qualify_packaged_update_commit.py", "build_packaged_update_trigger.py", "verify_packaged_observer_source.py",
          "stop_quit_ui_smoke.py", "geph_owned_lifecycle_smoke.py")


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
    public = ("public_update_ax.py", "public_update_ui_preflight.py", "public_update_preview33_menu_smoke.py",
              "public_update_observer.py", "public_update_preview33_pair_smoke.py", "public_update_visibility.py")
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
            require(exact_equal(pair, PAIR), "public qualification pair differs from pinned .32 -> .33")
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
