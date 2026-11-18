"""Tests for indenture.

These are written against the claims the README makes, one test per claim, so
that a claim that stops being true fails here rather than in someone else's
repository.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indenture import (  # noqa: E402
    EXIT_DENIED,
    EXIT_LEDGER,
    GENESIS,
    Indenture,
    Policy,
    canonical,
)

HERE = Path(__file__).resolve().parent.parent


@pytest.fixture()
def ind(tmp_path: Path) -> Indenture:
    i = Indenture(tmp_path / ".indenture")
    i.init()
    return i


# --------------------------------------------------------------------------- #
# Authorize
# --------------------------------------------------------------------------- #
def test_default_is_deny_when_no_rule_matches(ind: Indenture) -> None:
    d = ind.authorize("qa", "architect", kind="nonsense-kind")
    assert not d.allowed
    assert d.rule == "default"


def test_there_is_no_way_to_make_the_default_allow_implicitly(tmp_path: Path) -> None:
    """An absent `default` key must mean deny, not "unspecified"."""
    root = tmp_path / ".indenture"
    root.mkdir()
    (root / "policy.json").write_text(json.dumps({"actors": {}, "rules": []}))
    assert Policy.load(root / "policy.json").default == "deny"


def test_irreversible_lane_is_refused_by_the_shipped_policy(ind: Indenture) -> None:
    d = ind.authorize("backend", "deploy", kind="work")
    assert not d.allowed
    assert "irreversible" in d.reason


def test_an_allowed_handoff_is_allowed(ind: Indenture) -> None:
    d = ind.authorize("backend", "qa", kind="review_request")
    assert d.allowed, d.reason


def test_unknown_actor_is_refused_on_a_handoff(ind: Indenture) -> None:
    d = ind.authorize("human", "ghost", kind="work")
    assert not d.allowed
    assert d.rule == "unknown-actor"


def test_unknown_actor_is_recorded_not_refused_on_a_state_write(ind: Indenture) -> None:
    """A write already happened. Refusing to record it is a hole in the trail."""
    entry = ind.write_state("notes.md", {"a": 1}, by="ghost")
    assert entry["unknown_actor"] is True
    assert ind.entries()[-1]["key"] == "notes.md"


def test_an_empty_policy_declares_nobody_known(tmp_path: Path) -> None:
    """Fail-closed: no actor list must not mean "every actor is fine"."""
    assert not Policy().known("backend")


def test_refusals_are_journaled(ind: Indenture) -> None:
    ind.authorize("backend", "deploy", kind="work")
    denials = ind.denials()
    assert len(denials) == 1
    assert denials[0]["decision"] == "deny"
    assert denials[0]["reason"]


def test_first_matching_rule_decides(tmp_path: Path) -> None:
    root = tmp_path / ".indenture"
    root.mkdir()
    (root / "policy.json").write_text(json.dumps({
        "default": "deny",
        "actors": {"a": {"lane": "contained"}, "b": {"lane": "contained"}},
        "rules": [
            {"from": "a", "to": "b", "allow": False, "reason": "first wins"},
            {"from": "a", "to": "b", "allow": True, "reason": "never reached"},
        ],
    }))
    d = Indenture(root).authorize("a", "b")
    assert not d.allowed
    assert d.reason == "first wins"


# --------------------------------------------------------------------------- #
# Journal and integrity
# --------------------------------------------------------------------------- #
def test_first_entry_links_to_genesis(ind: Indenture) -> None:
    ind.note("start")
    assert ind.entries()[0]["prev"] == GENESIS


def test_chain_is_intact_after_a_normal_run(ind: Indenture) -> None:
    ind.note("start")
    ind.authorize("backend", "qa", kind="review_request")
    ind.write_state("contracts.md", {"schema": 1}, by="data")
    ok, problems = ind.verify()
    assert ok, problems


def test_an_edited_entry_is_detected_at_that_entry(ind: Indenture) -> None:
    ind.note("start")
    ind.write_state("contracts.md", {"schema": 1}, by="data")
    ind.note("end")

    lines = ind.journal.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["by"] = "someone-else"
    lines[1] = json.dumps(tampered, ensure_ascii=False)
    ind.journal.write_text("\n".join(lines) + "\n")

    ok, problems = ind.verify()
    assert not ok
    assert any(seq == 1 and "altered" in what for seq, what in problems)


def test_a_deleted_entry_is_detected_at_the_broken_link(ind: Indenture) -> None:
    for n in range(4):
        ind.note(f"n{n}")
    lines = ind.journal.read_text().splitlines()
    del lines[2]
    ind.journal.write_text("\n".join(lines) + "\n")

    ok, problems = ind.verify()
    assert not ok
    assert any("broken link" in what or "sequence gap" in what for _, what in problems)


def test_reordering_is_detected(ind: Indenture) -> None:
    for n in range(4):
        ind.note(f"n{n}")
    lines = ind.journal.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    ind.journal.write_text("\n".join(lines) + "\n")

    ok, problems = ind.verify()
    assert not ok


def test_an_unparseable_line_is_reported_not_ignored(ind: Indenture) -> None:
    ind.note("start")
    with ind.journal.open("a") as f:
        f.write("{ this is not json\n")
    ok, problems = ind.verify()
    assert not ok
    assert any("unparseable" in what for _, what in problems)


def test_canonical_form_is_byte_stable_across_key_order() -> None:
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1})


# --------------------------------------------------------------------------- #
# Payloads and redaction
# --------------------------------------------------------------------------- #
def test_payload_is_not_stored_by_default(ind: Indenture) -> None:
    ind.write_state("k", {"secret": "hunter2"}, by="data")
    entry = ind.entries()[-1]
    assert "payload" not in entry
    assert entry["payload_digest"]


def test_sensitive_keys_are_redacted_before_writing(ind: Indenture) -> None:
    ind.write_state("k", {"api_key": "sk-live-1", "ok": "visible"},
                    by="data", store_payload=True)
    entry = ind.entries()[-1]
    assert entry["payload"]["api_key"] == "<redacted>"
    assert entry["payload"]["ok"] == "visible"
    assert "sk-live-1" not in ind.journal.read_text()


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #
def test_replay_until_gives_the_state_as_it_stood_then(ind: Indenture) -> None:
    ind.write_state("k", {"v": 1}, by="data")
    mid = ind.entries()[-1]["seq"]
    ind.write_state("k", {"v": 2}, by="backend")

    assert ind.replay(until=mid)["k"]["by"] == "data"
    assert ind.replay()["k"]["by"] == "backend"


def test_blame_returns_every_write_oldest_first(ind: Indenture) -> None:
    ind.write_state("k", {"v": 1}, by="data")
    ind.write_state("k", {"v": 2}, by="backend")
    rows = ind.blame("k")
    assert [r["by"] for r in rows] == ["data", "backend"]


def test_why_returns_the_target_last_and_claims_no_causality(ind: Indenture) -> None:
    ind.authorize("backend", "qa", kind="review_request")
    ind.write_state("contracts.md", {"v": 1}, by="backend")
    target = ind.entries()[-1]["seq"]
    rows = ind.why(target)
    assert rows[-1]["seq"] == target
    assert len(rows) >= 2


def test_why_on_a_missing_entry_returns_nothing(ind: Indenture) -> None:
    assert ind.why(9999) == []


# --------------------------------------------------------------------------- #
# CLI contract — the exit codes the hook depends on
# --------------------------------------------------------------------------- #
def _cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HERE / "indenture.py"), "--dir", str(tmp_path / ".indenture"), *args],
        capture_output=True, text=True,
    )


def test_cli_allow_exits_zero(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    r = _cli(tmp_path, "check", "backend", "qa", "--kind", "review_request")
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_denial_exits_two_never_one(tmp_path: Path) -> None:
    """1 is reserved for the tool failing. A denial must be distinguishable."""
    _cli(tmp_path, "init")
    r = _cli(tmp_path, "check", "backend", "deploy")
    assert r.returncode == EXIT_DENIED
    assert "DENY" in r.stdout


def test_cli_verify_exits_four_on_a_broken_chain(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    _cli(tmp_path, "note", "start")
    journal = tmp_path / ".indenture" / "journal.jsonl"
    journal.write_text(journal.read_text().replace("start", "tampered"))
    r = _cli(tmp_path, "verify")
    assert r.returncode == EXIT_LEDGER


def test_cli_verify_exits_zero_on_an_intact_chain(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    _cli(tmp_path, "note", "start")
    r = _cli(tmp_path, "verify")
    assert r.returncode == 0, r.stdout


def test_reason_is_on_stdout_so_the_model_can_read_it(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    r = _cli(tmp_path, "check", "backend", "deploy")
    assert "irreversible" in r.stdout


# --------------------------------------------------------------------------- #
# The hook — the claim that enforcement is real
# --------------------------------------------------------------------------- #
def _hook(tmp_path: Path, command: str, actor: str = "backend") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HERE / "examples" / "claude_code_hook.py")],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}),
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "INDENTURE_ACTOR": actor,
             "INDENTURE_DIR": str(tmp_path / ".indenture")},
    )


def test_hook_blocks_a_watched_destructive_command(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    r = _hook(tmp_path, "kubectl apply -f prod.yaml")
    assert r.returncode == 2
    assert "denied" in r.stderr
    assert "Do not retry" in r.stderr


def test_hook_allows_an_unwatched_command(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    r = _hook(tmp_path, "npm test")
    assert r.returncode == 0


def test_hook_does_not_journal_unwatched_commands(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    before = len(Indenture(tmp_path / ".indenture").entries())
    _hook(tmp_path, "ls -la")
    after = len(Indenture(tmp_path / ".indenture").entries())
    assert before == after


def test_hook_does_not_match_a_watched_word_inside_another_command(tmp_path: Path) -> None:
    """`echo kubectl apply` is not a deployment."""
    _cli(tmp_path, "init")
    r = _hook(tmp_path, "echo kubectl apply -f prod.yaml")
    assert r.returncode == 0


def test_hook_failure_to_parse_is_not_a_policy_denial(tmp_path: Path) -> None:
    r = subprocess.run(
        [sys.executable, str(HERE / "examples" / "claude_code_hook.py")],
        input="not json", capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "INDENTURE_DIR": str(tmp_path / ".indenture")},
    )
    assert r.returncode == 1


# --------------------------------------------------------------------------- #
# Watched patterns — a default that cries wolf gets uninstalled
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("command", [
    "rm -rf node_modules",
    "rm -rf ./build",
    "rm -rf dist",
])
def test_hook_allows_everyday_cleanup(tmp_path: Path, command: str) -> None:
    _cli(tmp_path, "init")
    assert _hook(tmp_path, command).returncode == 0, command


@pytest.mark.parametrize("command", [
    "rm -rf /",
    "rm -rf ~/Documents",
    "rm -rf /var/lib/postgresql",
    "dd if=/dev/zero of=/dev/sda",
])
def test_hook_blocks_destruction_of_absolute_or_home_paths(tmp_path: Path, command: str) -> None:
    _cli(tmp_path, "init")
    assert _hook(tmp_path, command).returncode == 2, command


def test_every_hook_target_exists_in_the_shipped_policy(tmp_path: Path) -> None:
    """A target missing from the policy is refused as an unknown actor, which is
    the right outcome reached for the wrong reason — and the journal then records
    a misleading cause, which is worse in an audit tool than a wrong verdict."""
    import examples.claude_code_hook as hook  # noqa: PLC0415

    _cli(tmp_path, "init")
    declared = Indenture(tmp_path / ".indenture").policy.actors
    targets = {target for _pattern, target, _kind in hook.WATCHED}
    assert targets <= set(declared), targets - set(declared)
