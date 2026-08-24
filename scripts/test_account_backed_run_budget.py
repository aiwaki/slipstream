from __future__ import annotations

from datetime import date
import unittest

import account_backed_run_budget as budget


REPOSITORY = "aiwaki/slipstream"
UTC_DAY = date(2026, 8, 24)


def workflow_run(
    run_id: int,
    workflow: str,
    created_at: str,
    *,
    run_attempt: int = 1,
) -> dict:
    return {
        "created_at": created_at,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_repository": {"full_name": REPOSITORY},
        "id": run_id,
        "path": workflow,
        "run_attempt": run_attempt,
    }


def payloads(*runs: dict) -> dict[str, dict]:
    values = {
        workflow: {"total_count": 0, "workflow_runs": []}
        for workflow in budget.ACCOUNT_BACKED_WORKFLOWS
    }
    for run in runs:
        value = values[run["path"]]
        value["workflow_runs"].append(run)
        value["total_count"] += 1
    return values


class AccountBackedRunBudgetTests(unittest.TestCase):
    def verify(self, current_run_id: int, runs: dict[str, dict]) -> dict:
        return budget.verify_daily_budget(
            repository=REPOSITORY,
            utc_day=UTC_DAY,
            current_run_id=current_run_id,
            current_run_attempt=1,
            payloads=runs,
        )

    def test_first_three_mixed_dispatches_are_allowed(self) -> None:
        runs = payloads(
            workflow_run(
                101,
                budget.RELEASE_READINESS_WORKFLOW,
                "2026-08-24T00:00:01Z",
            ),
            workflow_run(
                102,
                budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW,
                "2026-08-24T01:00:00Z",
            ),
            workflow_run(
                103,
                budget.RELEASE_READINESS_WORKFLOW,
                "2026-08-24T02:00:00Z",
            ),
        )
        self.assertEqual(self.verify(101, runs)["current_position"], 1)
        self.assertEqual(self.verify(102, runs)["current_position"], 2)
        result = self.verify(103, runs)
        self.assertEqual(result["current_position"], 3)
        self.assertEqual(result["limit"], 3)

    def test_fourth_dispatch_is_rejected(self) -> None:
        runs = payloads(
            *[
                workflow_run(
                    100 + index,
                    (
                        budget.RELEASE_READINESS_WORKFLOW
                        if index % 2
                        else budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW
                    ),
                    f"2026-08-24T0{index}:00:00Z",
                )
                for index in range(1, 5)
            ]
        )
        with self.assertRaisesRegex(ValueError, "position 4, limit is 3"):
            self.verify(104, runs)

    def test_equal_timestamps_are_ordered_by_run_id(self) -> None:
        timestamp = "2026-08-24T03:00:00Z"
        runs = payloads(
            workflow_run(103, budget.RELEASE_READINESS_WORKFLOW, timestamp),
            workflow_run(101, budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW, timestamp),
            workflow_run(104, budget.RELEASE_READINESS_WORKFLOW, timestamp),
            workflow_run(102, budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW, timestamp),
        )
        self.assertEqual(self.verify(103, runs)["current_position"], 3)
        with self.assertRaisesRegex(ValueError, "position 4"):
            self.verify(104, runs)

    def test_failed_cancelled_and_skipped_dispatches_still_consume_rank(
        self,
    ) -> None:
        runs = [
            workflow_run(
                101,
                budget.RELEASE_READINESS_WORKFLOW,
                "2026-08-24T01:00:00Z",
            ),
            workflow_run(
                102,
                budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW,
                "2026-08-24T02:00:00Z",
            ),
            workflow_run(
                103,
                budget.RELEASE_READINESS_WORKFLOW,
                "2026-08-24T03:00:00Z",
            ),
        ]
        for run, conclusion in zip(runs, ("failure", "cancelled", "skipped")):
            run.update({"conclusion": conclusion, "status": "completed"})
        self.assertEqual(
            self.verify(103, payloads(*runs))["current_position"],
            3,
        )

    def test_rerun_attempt_is_rejected_before_counting(self) -> None:
        run = workflow_run(
            101,
            budget.RELEASE_READINESS_WORKFLOW,
            "2026-08-24T01:00:00Z",
            run_attempt=2,
        )
        with self.assertRaisesRegex(ValueError, "reruns are prohibited"):
            budget.verify_daily_budget(
                repository=REPOSITORY,
                utc_day=UTC_DAY,
                current_run_id=101,
                current_run_attempt=2,
                payloads=payloads(run),
            )

    def test_current_run_must_be_present_once(self) -> None:
        runs = payloads(
            workflow_run(
                101,
                budget.RELEASE_READINESS_WORKFLOW,
                "2026-08-24T01:00:00Z",
            )
        )
        with self.assertRaisesRegex(ValueError, "current workflow run is missing"):
            self.verify(102, runs)

        duplicate = workflow_run(
            101,
            budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW,
            "2026-08-24T02:00:00Z",
        )
        runs[budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW] = {
            "total_count": 1,
            "workflow_runs": [duplicate],
        }
        with self.assertRaisesRegex(ValueError, "duplicate run ID"):
            self.verify(101, runs)

    def test_incomplete_or_wrong_api_evidence_fails_closed(self) -> None:
        run = workflow_run(
            101,
            budget.RELEASE_READINESS_WORKFLOW,
            "2026-08-24T01:00:00Z",
        )
        runs = payloads(run)
        runs[budget.RELEASE_READINESS_WORKFLOW]["total_count"] = 2
        with self.assertRaisesRegex(ValueError, "response is incomplete"):
            self.verify(101, runs)

        runs = payloads(run)
        run["event"] = "push"
        with self.assertRaisesRegex(ValueError, "non-dispatch"):
            self.verify(101, runs)

    def test_out_of_day_or_wrong_repository_evidence_fails_closed(self) -> None:
        run = workflow_run(
            101,
            budget.RELEASE_READINESS_WORKFLOW,
            "2026-08-23T23:59:59Z",
        )
        with self.assertRaisesRegex(ValueError, "outside UTC day"):
            self.verify(101, payloads(run))

        run["created_at"] = "2026-08-24T00:00:00Z"
        run["head_repository"] = {"full_name": "someone/else"}
        with self.assertRaisesRegex(ValueError, "another repository"):
            self.verify(101, payloads(run))

        run["head_repository"] = "not an object"
        with self.assertRaisesRegex(ValueError, "another repository"):
            self.verify(101, payloads(run))

    def test_wrong_path_or_branch_evidence_fails_closed(self) -> None:
        run = workflow_run(
            101,
            budget.RELEASE_READINESS_WORKFLOW,
            "2026-08-24T00:00:00Z",
        )
        runs = payloads(run)
        run["path"] = budget.OWNED_GEPH_DIAGNOSTIC_WORKFLOW
        with self.assertRaisesRegex(ValueError, "wrong workflow path"):
            self.verify(101, runs)

        run["path"] = budget.RELEASE_READINESS_WORKFLOW
        run["head_branch"] = "feature"
        with self.assertRaisesRegex(ValueError, "non-main"):
            self.verify(101, runs)


if __name__ == "__main__":
    unittest.main()
