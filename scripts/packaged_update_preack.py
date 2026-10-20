"""One disposable pre-ACK fault; no fabricated receipt or root decision.

Only the separately guarded driver may instantiate this observer. Failure after
STOP retains state for runner destruction; it never turns a missed ACK window
into a successful fault or sends a recovery signal to an uncertain process.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import signal
import stat
import time

from native_root_update import Native, Refused, digest, require
from packaged_update_observer import (Observer, exact_equal,
    pre_ack_candidate, private_json, same_process, validate_journal)


MODE = "kill-successor-before-ack"


def stopped_candidate(pinned, journal, ack, root, current):
    # Reuse the original live snapshot to bind the newly read journal/root
    # identity. The fresh process observation must separately prove STOP.
    pre_ack_candidate(journal, ack, root, pinned, pinned)
    require(same_process(pinned, current) and current["state"] == "T",
            "stopped successor PID/UID/birth/argv changed or is not stopped")
    return current


def exact_old_tray(current, journal, uid, failed_new_pid):
    # The rollback receipt's successor_pid is failed NEW, never relaunched OLD.
    return (current is not None and current["uid"] == uid
            and current["state"] not in {"T", "Z"}
            and current["pid"] not in {failed_new_pid, journal["initiator_pid"]}
            and current["command"] == journal["target"] + "/Contents/MacOS/slipstream")


class PreAckObserver(Observer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fault_process = self.rollback_receipt = None

    def setup_observation(self):
        require(self.args.mode == MODE, "pre-ACK mode required")
        self.authenticate_observation()

    def fault_window(self):
        journal = private_json(self.journal_path, self.uid)
        require(journal is not None, "missed pre-ACK window: journal absent")
        self.bind(journal)
        ack = private_json(self.ack_path, self.uid, limit=8192)
        root = self.status()
        require(journal["phase"] == "successor_launched" and ack is None
                and root["phase"] == "ready" and root["decision"] is None
                and root["writer_quiescent"] is True,
                "missed pre-ACK window: ACK, decision or phase already changed")
        return journal, ack, root

    def inject_pre_ack_exit(self, *, send=None, clock=time.monotonic,
                            wallclock=time.time, sleep=time.sleep):
        require(self.fault_process is None and self.watchdog is not None,
                "fault may run once, only after actual watchdog observation")
        send = os.kill if send is None else send
        journal, ack, root = self.fault_window()
        first = self.process_snapshot(journal["successor_pid"])
        require(digest(self.target / "Contents/MacOS/slipstream") == self.expected["new"]["app_executable_sha256"],
                "fault target is not pinned NEW executable")
        second = self.process_snapshot(journal["successor_pid"])
        pinned = pre_ack_candidate(journal, ack, root, first, second)
        require(wallclock() < min(journal["successor_deadline_unix"], root["deadline_unix"]) and clock() < self.deadline - 90,
                "pre-ACK fault deadline exhausted")
        send(pinned["pid"], signal.SIGSTOP)
        self.record("fault_stop_sent", pinned)
        stop_deadline = min(clock() + 2, self.deadline - 90)
        while clock() < stop_deadline:
            current = self.process_snapshot(pinned["pid"])
            require(same_process(pinned, current) and current["state"] != "Z",
                    "successor changed or exited before STOP confirmation")
            if current["state"] == "T":
                break
            sleep(0.01)
        else:
            raise Refused("STOP confirmation deadline exhausted; no KILL permitted")
        # Re-read all mutable decision evidence after the process is stopped.
        # Any missed window fails and retains the runner; there is no retry.
        journal, ack, root = self.fault_window()
        stopped = stopped_candidate(pinned, journal, ack, root,
                                    self.process_snapshot(pinned["pid"]))
        require(wallclock() < min(journal["successor_deadline_unix"], root["deadline_unix"]),
                "pre-ACK/root deadline elapsed while stopped")
        require(private_json(self.ack_path, self.uid, limit=8192) is None,
                "missed pre-ACK window: ACK appeared after STOP")
        self.record("fault_stopped_window", {"process": stopped, "journal": journal, "root": root})
        send(pinned["pid"], signal.SIGKILL)
        self.fault_process = copy.deepcopy(pinned)
        killed_unix = wallclock()
        self.record("fault_kill_sent", {"process": pinned, "unix": killed_unix})
        require(killed_unix < min(journal["successor_deadline_unix"], root["deadline_unix"]),
                "fault crossed pre-ACK/root deadline; causal result incomplete")

    def read_rollback_receipt(self):
        require(self.identity is not None and self.fault_process is not None, "fault identity missing")
        path = self.state / ("app-update-transaction-failed-" + self.identity["nonce"] + ".json")
        value = private_json(path, self.uid)
        require(value is not None, "production rollback receipt missing")
        validate_journal(value, self.expected, self.identity, self.uid, self.state, self.target, self.watchdog_hash)
        require(value["phase"] == "old_relaunched"
                and value["successor_pid"] == self.fault_process["pid"]
                and value["successor_started"] == self.fault_process["started"]
                and value["daemon_update"]["manifest_sha256"] == self.manifest
                and value["daemon_update"]["action"] == "abort",
                "rollback receipt does not bind failed NEW and production abort")
        require(self.rollback_receipt is None or exact_equal(self.rollback_receipt, value),
                "completed rollback receipt changed")
        self.rollback_receipt = copy.deepcopy(value)
        self.record("rollback_receipt", value)
        return value

    def final_old_app(self):
        receipt = self.read_rollback_receipt()
        require(self.tproxy._daemon_update_tree(self.target, readable=True) == self.expected["old"]["bundle_tree_sha256"],
                "restored app tree differs from authenticated OLD")
        for path in (self.journal_path, self.ack_path, self.stage, Path(receipt["backup"]), self.agent):
            require(not os.path.lexists(path), "rollback cleanup incomplete: " + str(path))
        require(self.watchdog_finished(), "rollback watchdog is not terminal")
        require(self.process_snapshot(self.fault_process["pid"]) is None,
                "failed NEW PID remains or has been reused")
        result = self.run(["/usr/bin/pgrep", "-x", "slipstream"], check=False)
        values = result.stdout.decode().split()
        require(result.returncode == 0 and len(values) == 1 and values[0].isdigit(),
                "one independently observed OLD tray must be alive")
        current = self.process_snapshot(int(values[0]))
        require(exact_old_tray(current, receipt, self.uid, self.fault_process["pid"]),
                "restored OLD tray identity mismatch")
        require(self.tray is None or same_process(self.tray, current), "restored OLD tray changed")
        self.tray = current
        self.record("final_old_app", {"process": current, "bundle_tree_sha256": self.expected["old"]["bundle_tree_sha256"]})

    def qualify_app(self, *, clock=time.monotonic, sleep=time.sleep):
        require(self.args.mode == MODE, "pre-ACK mode required")
        while clock() < self.deadline - 90:
            journal = self.observe_once()
            require(self.ack is None, "missed pre-ACK window: successor ACK observed")
            root = self.root_status
            require(root is None or root["decision"] != "commit", "missed pre-ACK window: root committed")
            if self.fault_process is None:
                require(root is None or root["decision"] is None, "transaction aborted before the injected fault")
                if journal is not None and journal["phase"] == "successor_launched" and root is not None:
                    self.inject_pre_ack_exit()
            elif (journal is None and self.receipt is not None and root is not None
                  and root["phase"] == "aborted" and root["decision"] == "abort"
                  and root["writer_quiescent"] is True and self.watchdog_finished()):
                require(not same_process(self.initiator, self.process_snapshot(self.initiator["pid"])),
                        "trigger remains alive after rollback")
                self.final_old_app()
                self.prove("old", exact_snapshot=True)
                self.final_old_app()
                return {"packaged_transaction_qualified": True, "public_pair_qualified": False,
                        "successor_exit_before_ack_rollback_qualified": True, "side": "old"}
            sleep(0.02)
        self.retain_completion_diagnostic()
        raise Refused("pre-ACK rollback deadline exhausted; observation incomplete")

    def cleanup_rollback(self, *, send=None, clock=time.monotonic, sleep=time.sleep):
        self.final_old_app()
        root = self.status()
        require(root["phase"] == "aborted" and root["decision"] == "abort" and root["writer_quiescent"] is True,
                "cleanup requires proven quiescent root abort")
        info = self.target.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid,
                "restored app ownership mismatch")
        require(self.created == [{"path": self.target, "sha256": self.expected["old"]["bundle_tree_sha256"],
                "inode": (info.st_dev, info.st_ino), "complete": True}],
                "restored OLD is not the initially installed app inode")
        current = self.process_snapshot(self.tray["pid"])
        require(same_process(current, self.tray)
                and exact_old_tray(current, self.rollback_receipt, self.uid, self.fault_process["pid"]),
                "OLD tray identity changed before cleanup")
        send = os.kill if send is None else send
        send(current["pid"], signal.SIGTERM)
        stop_deadline = min(clock() + 15, self.deadline)
        while clock() < stop_deadline:
            current = self.process_snapshot(self.tray["pid"])
            if current is None:
                break
            require(same_process(current, self.tray), "OLD tray PID reused during cleanup")
            sleep(0.1)
        else:
            raise Refused("OLD tray did not exit; no forced cleanup")
        require(self.run(["/usr/bin/pgrep", "-x", "slipstream"], check=False).returncode == 1,
                "tray remains after rollback cleanup")
        # Rollback renames the original OLD back. Preserve its initial inode;
        # unlike commit cleanup, no newly observed target is adopted here.
        self.mailbox = Path(self.tproxy._DAEMON_UPDATE_REQUESTS) / f"{self.uid}-{self.identity['nonce']}"
        Native.teardown(self)
