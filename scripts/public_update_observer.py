#!/usr/bin/env python3
"""Observe the normal OLD tray's schema-2 update, without a prepare adapter.

Only the disposable driver launches OLD or clicks its menu. These adapters reuse
packaged app/root/ACK proofs, but bind the journal to the already observed tray
and require its ordinary exit instead of manufacturing a trigger receipt.
"""
from __future__ import annotations

import os
import time

from native_root_update import Refused, digest, require
from packaged_update_observer import Observer, committed, same_process
from packaged_update_preack import MODE, PreAckObserver


class PublicInitiator:
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
        # This does not press a dialog or imply that one was visibly delivered.
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
            "administrator_dialog_interaction_qualified": False})


class PublicObserver(PublicInitiator, Observer):
    def wait_transaction(self, *, clock=time.monotonic, sleep=time.sleep):
        while clock() < self.deadline - 90:
            journal = self.observe_once()
            if self.root_status is not None:
                require(self.root_status["decision"] != "abort", "normal public update aborted")
            if self.original_exited and journal is None and self.identity is not None:
                root = self.status()
                if root["phase"] == "committed" and root["writer_quiescent"] and self.watchdog_finished():
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
