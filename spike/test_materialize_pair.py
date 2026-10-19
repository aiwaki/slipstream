"""No commands, extraction or product runtime execution in these tests."""
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(DIRECTORY))
import materialize_pair as pair
from native_root_update import Refused


def environment():
    return {"OLD_SOURCE_SHA": "a" * 40, "NEW_SOURCE_SHA": "b" * 40,
        "OLD_MANIFEST_SHA": "c" * 64, "NEW_MANIFEST_SHA": "d" * 64,
        "OLD_RUN_ID": "123", "NEW_RUN_ID": "124",
        "OLD_RUN_ATTEMPT": "1", "NEW_RUN_ATTEMPT": "2"}


def test_dispatch_pins_keep_exact_run_attempt_and_manifest():
    pins = pair.pins_from_environment(environment())
    assert pins["old"]["run_id"] == 123
    assert pins["new"] == {"source_commit": "b" * 40,
        "candidate_manifest_sha256": "d" * 64, "run_id": 124, "run_attempt": 2}


@pytest.mark.parametrize("key,value", [("OLD_SOURCE_SHA", "main"),
    ("NEW_SOURCE_SHA", "a" * 40), ("OLD_MANIFEST_SHA", "bad"),
    ("OLD_RUN_ATTEMPT", "0"), ("NEW_RUN_ID", "123"), ("NEW_RUN_ID", "124; command")])
def test_dispatch_pins_reject_ambiguous_or_ineffective_pair(key, value):
    env = environment()
    env[key] = value
    with pytest.raises(Refused):
        pair.pins_from_environment(env)


def backend(events, *, bad_tree=False, reject=False):
    def verify(pinned, directory):
        events.append(("verify", directory.name))
        if reject:
            raise Refused("untrusted candidate")
        return {"candidate_id": pinned["source_commit"], "app_tree_sha256": "c" * 64}

    def run(argv, timeout):
        assert argv[:3] == ["/usr/bin/ditto", "-x", "-k"]
        events.append(("extract", argv[-1].name))

    return SimpleNamespace(verified_manifest=verify, run=run,
        candidate=SimpleNamespace(deterministic_tree_sha256=lambda app: "b" * 64 if bad_tree else "c" * 64))


def test_authentication_precedes_each_extract_and_no_installer_is_called(tmp_path):
    events = []
    result = pair.materialize(backend(events), pair.pins_from_environment(environment()), tmp_path)
    assert events == [("verify", "old-candidate"), ("extract", "old-app"),
                      ("verify", "new-candidate"), ("extract", "new-app")]
    assert [item["side"] for item in result] == ["old", "new"]


def test_untrusted_manifest_does_not_create_or_extract_application(tmp_path):
    events = []
    with pytest.raises(Refused, match="untrusted"):
        pair.materialize(backend(events, reject=True), pair.pins_from_environment(environment()), tmp_path)
    assert events == [("verify", "old-candidate")]
    assert not list(tmp_path.iterdir())


def test_tree_mismatch_stops_before_second_candidate(tmp_path):
    events = []
    with pytest.raises(Refused, match="extracted app differs"):
        pair.materialize(backend(events, bad_tree=True), pair.pins_from_environment(environment()), tmp_path)
    assert events == [("verify", "old-candidate"), ("extract", "old-app")]
