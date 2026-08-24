#!/usr/bin/env python3
"""Fail closed when the daily account-backed workflow budget is exhausted."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import json
from pathlib import Path


MAX_ACCOUNT_BACKED_DISPATCHES_PER_UTC_DAY = 3
RELEASE_READINESS_WORKFLOW = ".github/workflows/release-readiness.yml"
OWNED_GEPH_DIAGNOSTIC_WORKFLOW = (
    ".github/workflows/owned-geph-qualification.yml"
)
ACCOUNT_BACKED_WORKFLOWS = (
    RELEASE_READINESS_WORKFLOW,
    OWNED_GEPH_DIAGNOSTIC_WORKFLOW,
)


def _positive_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _utc_date(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("UTC date must use YYYY-MM-DD") from exc
    if parsed.isoformat() != value:
        raise ValueError("UTC date must use YYYY-MM-DD")
    return parsed


def _created_at(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("workflow run created_at must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("workflow run created_at is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError("workflow run created_at must be UTC")
    return parsed


def _read_payload(path: Path, workflow: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{workflow} runs response is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{workflow} runs response must be an object")
    return value


def verify_daily_budget(
    *,
    repository: str,
    utc_day: date,
    current_run_id: int,
    current_run_attempt: int,
    payloads: dict[str, dict],
) -> dict:
    """Validate complete daily run lists and reserve the current run's rank."""

    if (
        not isinstance(repository, str)
        or repository.count("/") != 1
        or not all(repository.split("/"))
    ):
        raise ValueError("repository must use owner/name")
    current_run_id = _positive_integer(current_run_id, "current run ID")
    current_run_attempt = _positive_integer(
        current_run_attempt, "current run attempt"
    )
    if current_run_attempt != 1:
        raise ValueError(
            "account-backed workflow reruns are prohibited; dispatch a fresh run"
        )
    if set(payloads) != set(ACCOUNT_BACKED_WORKFLOWS):
        raise ValueError("daily budget requires both exact account-backed workflows")

    observed: list[tuple[datetime, int, str, int]] = []
    observed_ids: set[int] = set()
    for workflow in ACCOUNT_BACKED_WORKFLOWS:
        payload = payloads[workflow]
        if not isinstance(payload, dict):
            raise ValueError(f"{workflow} runs response must be an object")
        total_count = payload.get("total_count")
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < 0
        ):
            raise ValueError(f"{workflow} total_count is invalid")
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise ValueError(f"{workflow} workflow_runs must be a list")
        if total_count != len(runs):
            raise ValueError(
                f"{workflow} daily run response is incomplete; refusing quota use"
            )

        for run in runs:
            if not isinstance(run, dict):
                raise ValueError(f"{workflow} contains a non-object workflow run")
            run_id = _positive_integer(run.get("id"), "workflow run ID")
            if run_id in observed_ids:
                raise ValueError("daily workflow run lists contain a duplicate run ID")
            observed_ids.add(run_id)
            if run.get("event") != "workflow_dispatch":
                raise ValueError("daily budget response contains a non-dispatch run")
            if run.get("path") != workflow:
                raise ValueError("daily budget response contains a wrong workflow path")
            if run.get("head_branch") != "main":
                raise ValueError("daily budget response contains a non-main run")
            head_repository = run.get("head_repository")
            if (
                not isinstance(head_repository, dict)
                or head_repository.get("full_name") != repository
            ):
                raise ValueError("daily budget response belongs to another repository")
            created_at = _created_at(run.get("created_at"))
            if created_at.date() != utc_day:
                raise ValueError("daily budget response contains a run outside UTC day")
            run_attempt = _positive_integer(
                run.get("run_attempt"), "workflow run attempt"
            )
            observed.append((created_at, run_id, workflow, run_attempt))

    observed.sort(key=lambda item: (item[0], item[1]))
    matching = [item for item in observed if item[1] == current_run_id]
    if len(matching) != 1:
        raise ValueError("current workflow run is missing from the complete daily lists")
    if matching[0][3] != current_run_attempt:
        raise ValueError("current workflow run attempt does not match GitHub metadata")

    position = observed.index(matching[0]) + 1
    if position > MAX_ACCOUNT_BACKED_DISPATCHES_PER_UTC_DAY:
        raise ValueError(
            "daily account-backed workflow budget exhausted: "
            f"run is position {position}, limit is "
            f"{MAX_ACCOUNT_BACKED_DISPATCHES_PER_UTC_DAY}"
        )

    return {
        "current_position": position,
        "limit": MAX_ACCOUNT_BACKED_DISPATCHES_PER_UTC_DAY,
        "observed_dispatches": len(observed),
        "result": "allowed",
        "utc_date": utc_day.isoformat(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--repository", required=True)
    verify.add_argument("--utc-date", required=True)
    verify.add_argument("--current-run-id", required=True, type=int)
    verify.add_argument("--current-run-attempt", required=True, type=int)
    verify.add_argument("--release-readiness-runs", required=True, type=Path)
    verify.add_argument("--owned-geph-runs", required=True, type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = verify_daily_budget(
            repository=args.repository,
            utc_day=_utc_date(args.utc_date),
            current_run_id=args.current_run_id,
            current_run_attempt=args.current_run_attempt,
            payloads={
                RELEASE_READINESS_WORKFLOW: _read_payload(
                    args.release_readiness_runs, RELEASE_READINESS_WORKFLOW
                ),
                OWNED_GEPH_DIAGNOSTIC_WORKFLOW: _read_payload(
                    args.owned_geph_runs, OWNED_GEPH_DIAGNOSTIC_WORKFLOW
                ),
            },
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
