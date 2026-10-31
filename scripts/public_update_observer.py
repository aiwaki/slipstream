#!/usr/bin/env python3
"""Observe the normal OLD tray's schema-2 update, without a prepare adapter.

Only the disposable driver launches OLD or clicks its menu. These adapters reuse
packaged app/root/ACK proofs, but bind the journal to the already observed tray
and require its ordinary exit instead of manufacturing a trigger receipt.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from native_root_update import Refused, digest, guard, modules, readonly_runtime_proof, require
from packaged_update_observer import Observer, committed, private_bytes, same_process
from packaged_update_preack import MODE, PreAckObserver
import stop_quit_ui_smoke as native_ui

UPDATE_PROMPT = "Slipstream needs administrator access to update its application and background daemon together."


def cancel_dialog(actor, *, timeout, clock=time.monotonic, sleep=time.sleep):
    """One definitive native Cancel; only known pre-click AX errors may retry."""
    until = clock() + timeout
    while clock() < until:
        response = actor(UPDATE_PROMPT, cancel=True, timeout=min(15, until - clock()))
        require(clock() < until, "Cancel observation arrived after GUI deadline")
        if response == "cancelled":
            return {"mode": "cancel", "cancelled": True, "cancel_clicks": 1}
        if isinstance(response, dict):
            require(set(response) == {"state", "stage", "code"} and response.get("state") == "ax_error"
                    and type(response.get("code")) is int
                    and response.get("stage") in native_ui.AUTH_RETRY_STAGES
                    and response.get("code") in native_ui.AUTH_RETRY_CODES,
                    "native Cancel outcome uncertain; no retry")
        else:
            require(response == "absent", "unexpected native Cancel outcome; no retry")
        sleep(min(0.2, max(0, until - clock())))
    raise Refused("native Cancel GUI deadline exhausted; pending authorization retained")


def readonly_cancel_proof(tproxy, expected_sha, nonce=None):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha)
            and (nonce is None or re.fullmatch(r"[0-9a-f]{32}", nonce)), "invalid Cancel proof identity")
    base = Path(tproxy._DAEMON_UPDATE_ROOT)
    if os.path.lexists(base):
        info = base.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe root operation directory")
    require(not os.path.lexists(base / "active.json"), "Cancel left an active root operation")
    if nonce is not None:
        require(not os.path.lexists(base / nonce) and not os.path.lexists(base / (".prepare-" + nonce)),
                "Cancel left root preparation")
    value = readonly_runtime_proof(tproxy, expected_sha)
    value.update(current_tree_sha256=tproxy._daemon_update_tree(tproxy.INSTALL_DIR),
                 nonce=nonce, active_index_absent=True, root_operation_absent=nonce is not None)
    return value


class PublicInitiator:
    def cancel_runtime_proof(self, nonce=None):
        command = ["/usr/bin/env", "CI=true", "GITHUB_ACTIONS=true", "SLIPSTREAM_DISPOSABLE_CI=1", "RUNNER_OS=macOS",
                   sys.executable, Path(__file__).resolve(), "--repo", self.args.repo,
                   "--cancel-proof", self.expected["old"]["daemon_sha256"]]
        if nonce is not None:
            command += ["--nonce", nonce]
        response = self.sudo(*command, timeout=30)
        require(len(response.stdout) <= 32768, "Cancel runtime proof exceeds bound")
        return json.loads(response.stdout)

    def configure_authorization(self, username, password, *, mode):
        require(mode in {"confirm", "cancel"} and username and password, "invalid authorization mode")
        require(not getattr(self, "authorization_configured", False), "authorization already configured")
        require(self.identity is None and not self.click_attempted, "authorization configured after update intent")
        self.authorization_configured = True
        self.authorization_mode, self._authorization_credentials = mode, (username, password)
        self.authorization = None
        self.authorization_confirmed = False
        self.cancelled_proof = None
        self.authorization_children = []
        self.cancel_log_offset = (self.args.output_dir / "normal-old-tray.log").stat().st_size
        self.cancel_before = self.cancel_runtime_proof() if mode == "cancel" else None

    def interact_authorization(self, *, actor=None, clock=time.monotonic):
        if self.authorization is not None:
            return
        # Preparation has already recorded the exact nonce before macOS asks for
        # a password. Do not consume an unrelated or unbound system dialog.
        require(self.identity is not None and self.last_journal["phase"] == "prepared",
                "authorization dialog is not bound to a Prepared app transaction")
        require(len(self.authorization_children) == 1, "one owned authorization child required")
        actor = actor or native_ui.auth_action
        timeout = min(90, self.deadline - 90 - clock())
        require(timeout > 0, "authorization GUI budget exhausted")
        username, password = self._authorization_credentials
        evidence = {"mode": self.authorization_mode, "nonce": self.identity["nonce"],
                    "child": self.authorization_children[0], "gui_budget_seconds": timeout}
        self.authorization = evidence  # An uncertain interaction is never replayed.
        try:
            if self.authorization_mode == "cancel":
                evidence.update(cancel_dialog(actor, timeout=timeout))
            else:
                native_ui.authorize_until(lambda: True,
                    lambda prompt, **kwargs: actor(prompt, username=username, password=password, **kwargs),
                    result=evidence, prompt=UPDATE_PROMPT, timeout=timeout, require_submission=True)
                # Only native submission and disappearance are qualified here.
                # The existing root observer independently proves preparation.
                evidence["scope"] = "native_submission_and_prompt_disappearance"
                self.authorization_confirmed = True
        finally:
            self._authorization_credentials = None
            self.record("native_authorization", evidence)

    def wait_cancelled(self, *, clock=time.monotonic, sleep=time.sleep):
        require(self.authorization_mode == "cancel", "native Cancel mode required")
        while clock() < self.deadline - 90:
            journal = self.observe_once()
            require(not self.original_exited and self.root_status is None and self.ack is None,
                    "Cancel unexpectedly changed app or root runtime")
            if journal is None and self.identity is not None and self.authorization and self.authorization.get("cancelled"):
                raw = private_bytes(self.args.output_dir / "normal-old-tray.log", self.uid,
                                    limit=2 * 1024 * 1024, writing=True)
                if raw is None or b"update authorization cancelled" not in raw[self.cancel_log_offset:]:
                    sleep(0.05)
                    continue
                paths = [self.journal_path, self.ack_path, self.stage, Path(self.last_journal["backup"]), self.agent]
                require(not any(os.path.lexists(path) for path in paths), "Cancel left local preparation")
                if self.authorization_children:
                    sleep(0.05)
                    continue
                current = self.process_snapshot(self.initiator["pid"])
                require(self.original_process.poll() is None and same_process(current, self.initiator)
                        and current["state"] not in {"Z", "T"}, "OLD tray changed after Cancel")
                tree = self.tproxy._daemon_update_tree(self.target, readable=True)
                require(tree == self.expected["old"]["bundle_tree_sha256"], "OLD bundle changed after Cancel")
                after = self.cancel_runtime_proof(self.identity["nonce"])
                before = self.cancel_before
                require(after["process"] == before["process"]
                        and after["proof"]["daemon_pid"] == before["proof"]["daemon_pid"]
                        and after["proof"]["daemon_sha256"] == before["proof"]["daemon_sha256"]
                        and after["current_tree_sha256"] == before["current_tree_sha256"],
                        "OLD daemon changed after Cancel")
                if after["proof"]["heartbeat_seq"] <= before["proof"]["heartbeat_seq"]:
                    sleep(0.25)
                    continue
                require(clock() < self.deadline - 90, "Cancel proof arrived after observation deadline")
                self.cancelled_proof = {"native_cancel_qualified": True, "nonce": self.identity["nonce"],
                    "original_process": current, "old_tree_sha256": tree, "before": before, "after": after,
                    "local_preparation_removed": True, "root_operation_absent": True}
                self.record("native_cancel", self.cancelled_proof)
                return self.cancelled_proof
            sleep(0.05)
        self.retain_public_diagnostic()
        raise Refused("native Cancel cleanup deadline exhausted; no retry permitted")

    def reset_after_cancel(self):
        require(self.cancelled_proof and self.cancelled_proof["nonce"] == self.identity["nonce"],
                "retry requires definitive native Cancel proof")
        require(self.menu.click_verified and self.original_process.poll() is None,
                "Cancel click or original tray outcome incomplete")
        require(not any(os.path.lexists(path) for path in (self.journal_path, self.ack_path, self.stage, self.agent)),
                "Cancel preparation reappeared")
        self.record("cancel_retry_admitted", {"cancelled_nonce": self.identity["nonce"]})
        for name in ("identity", "manifest", "operation", "mailbox", "stage", "last_journal", "root_status"):
            setattr(self, name, None)
        self.authorization_configured = False
        self.last_authorization_poll = 0.0
        self.menu.reset_after_cancel()

    def capture_original(self, process):
        require(self.initiator is None and self.identity is None, "original tray was already bound")
        require(not os.path.lexists(self.journal_path) and not os.path.lexists(self.ack_path),
                "public observer started after the transaction")
        executable = self.target / "Contents/MacOS/slipstream"
        current = self.process_snapshot(process.pid)
        require(current is not None and current["uid"] == self.uid and current["state"] not in {"T", "Z"}
                and current["command"] == str(executable), "normal OLD tray identity mismatch")
        require(digest(executable) == self.expected["old"]["app_executable_sha256"]
                and self.tproxy._daemon_update_tree(self.target, readable=True)
                == self.expected["old"]["bundle_tree_sha256"], "normal OLD bundle mismatch")
        self.watchdog_hash = digest(self.target / "Contents/MacOS/slipstream-update-watchdog")
        self.original_process, self.initiator = process, current
        self.original_exited = False
        self.last_authorization_poll = 0.0
        self.record("normal_old_tray", current)
        self.record("observer_ready", {"state_dir": str(self.state), "expected": self.expected,
                                      "initiator_kind": "normal_installed_app"})

    def observe_authorization(self, *, clock=time.monotonic):
        # Metadata only: never save AppleScript argv, authorization data or env.
        now = clock()
        if now - self.last_authorization_poll < 1:
            return
        self.last_authorization_poll = now
        result = self.run(["/usr/bin/pgrep", "-P", str(self.initiator["pid"]), "-x", "osascript"], check=False)
        values = result.stdout.decode().split()
        require(result.returncode in (0, 1) and not (result.returncode == 1 and values)
                and len(values) <= 4 and all(item.isdigit() for item in values),
                "authorization child metadata unavailable")
        processes = []
        for value in values:
            sample = self.run(["/bin/ps", "-p", value, "-o", "pid=,ppid=,uid=,lstart=,comm="], check=False)
            if sample.returncode == 1 and not sample.stdout.strip():
                continue
            fields = sample.stdout.decode().strip().split(None, 8)
            require(sample.returncode == 0 and len(fields) == 9 and fields[0] == value
                    and fields[1] == str(self.initiator["pid"]) and fields[2] == str(self.uid)
                    and fields[8] in {"osascript", "/usr/bin/osascript"},
                    "authorization child identity mismatch")
            processes.append({"pid": int(value), "ppid": self.initiator["pid"], "uid": self.uid,
                              "started": " ".join(fields[3:8]), "executable": "/usr/bin/osascript"})
        self.record("authorization_children", {"processes": processes, "dialog_interaction_qualified": False})
        self.authorization_children = processes
        if processes and self.identity is not None and getattr(self, "authorization_configured", False):
            self.interact_authorization()

    def read_receipt(self):
        # Called by the shared observer. There is deliberately no adapter receipt.
        self.menu.check_click()
        log = self.args.output_dir / "normal-old-tray.log"
        require(log.stat().st_size <= 2 * 1024 * 1024, "normal tray diagnostic log exceeded bound")
        code = self.original_process.poll()  # Reap this owned child before ps.
        current = self.process_snapshot(self.initiator["pid"])
        if code is None and (current is None or current["state"] == "Z"
                             or not same_process(current, self.initiator)):
            # Exit can race waitpid/ps; a zombie may already have lost its argv.
            # Only our own child status can resolve that observation. Recheck
            # after reaping so a reused PID is never accepted as disappearance.
            code = self.original_process.poll()
            if code is not None:
                current = self.process_snapshot(self.initiator["pid"])
        if code is None:
            require(same_process(current, self.initiator) and current["state"] != "Z", "original tray identity changed")
            self.observe_authorization()
            return
        require(code == 0 and current is None, "original tray did not exit normally or PID was reused")
        require(self.identity is not None, "original tray exited without an observed production transaction")
        if not self.original_exited and getattr(self, "visibility", None) is not None:
            self.visibility.set_phase("handoff")
        self.original_exited = True
        self.record("normal_old_exit", {"process": self.initiator, "returncode": code,
                                       "signal_sent_by_driver": False})

    def retain_public_diagnostic(self):
        if self.last_journal is not None:
            self.retain_completion_diagnostic()
        else:
            self.record("completion_diagnostic", {"journal_observed": False,
                "paths_present": {"journal": os.path.lexists(self.journal_path),
                                  "ack": os.path.lexists(self.ack_path)},
                "watchdog": "not_checked_before_journal"})
        self.record("public_completion", {"original_exited": getattr(self, "original_exited", False),
            "original_returncode": self.original_process.poll() if hasattr(self, "original_process") else None,
            "root_phase": self.root_status.get("phase") if self.root_status else None,
            "root_decision": self.root_status.get("decision") if self.root_status else None,
            "app_phase": self.last_journal.get("phase") if self.last_journal else None,
            "administrator_dialog_interaction_qualified": bool(getattr(self, "authorization_confirmed", False)
                or (getattr(self, "authorization", None) or {}).get("cancelled"))})


class PublicObserver(PublicInitiator, Observer):
    def wait_transaction(self, *, clock=time.monotonic, sleep=time.sleep):
        while clock() < self.deadline - 90:
            journal = self.observe_once()
            if self.root_status is not None:
                require(self.root_status["decision"] != "abort", "normal public update aborted")
            if self.original_exited and journal is None and self.identity is not None:
                root = self.status()
                if root["phase"] == "committed" and root["writer_quiescent"] and self.watchdog_finished():
                    require(self.authorization_confirmed, "native administrator interaction was not observed")
                    committed(root, self.ack)
                    return root
            sleep(0.02)
        self.retain_public_diagnostic()
        raise Refused("normal public update deadline exhausted; pending authorization/transaction retained")


class PublicPreAckObserver(PublicInitiator, PreAckObserver):
    def qualify_app(self, *, clock=time.monotonic, sleep=time.sleep):
        require(self.args.mode == MODE, "pre-ACK mode required")
        while clock() < self.deadline - 90:
            journal = self.observe_once()
            require(self.ack is None, "missed pre-ACK window: successor ACK observed")
            root = self.root_status
            require(root is None or root["decision"] != "commit", "missed pre-ACK window: root committed")
            if self.fault_process is None:
                require(root is None or root["decision"] is None, "transaction aborted before injected fault")
                if journal is not None and journal["phase"] == "successor_launched" and root is not None:
                    require(self.original_exited, "OLD tray exit not observed before successor fault")
                    require(self.authorization_confirmed, "native administrator interaction was not observed")
                    self.inject_pre_ack_exit()
            elif (journal is None and self.original_exited and root is not None
                  and root["phase"] == "aborted" and root["decision"] == "abort"
                  and root["writer_quiescent"] is True and self.watchdog_finished()):
                self.final_old_app()
                self.prove("old", exact_snapshot=True)
                self.final_old_app()
                return {"packaged_transaction_qualified": True, "public_pair_qualified": False,
                        "successor_exit_before_ack_rollback_qualified": True, "side": "old"}
            sleep(0.02)
        self.retain_public_diagnostic()
        raise Refused("normal public pre-ACK rollback deadline exhausted; observation incomplete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Disposable readonly OLD runtime proof for native Cancel")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--cancel-proof", required=True)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    guard(root=True)
    tproxy, _ = modules(args.repo)
    print(json.dumps(readonly_cancel_proof(tproxy, args.cancel_proof, args.nonce), sort_keys=True))
