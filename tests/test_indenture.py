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
    __version__,
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
def _hook(tmp_path: Path, command: str, actor: str = "backend",
          by_argv: bool = False, session: str = "s-1") -> subprocess.CompletedProcess:
    """Run the hook. by_argv passes the actor as a command-line argument, which
    is the portable path: `VAR=value command` is not valid on Windows."""
    argv = [sys.executable, str(HERE / "examples" / "claude_code_hook.py")]
    env = {"PATH": "/usr/bin:/bin", "INDENTURE_DIR": str(tmp_path / ".indenture")}
    if by_argv:
        argv.append(actor)
    else:
        env["INDENTURE_ACTOR"] = actor
    return subprocess.run(
        argv, input=json.dumps({"tool_name": "Bash", "session_id": session,
                                "tool_input": {"command": command}}),
        capture_output=True, text=True, env=env,
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


def test_hook_journals_unwatched_commands_once_per_session_and_never_again(
        tmp_path: Path) -> None:
    """Unwatched calls are not journaled individually — a journal that records
    every `ls` is one nobody reads. The single exception is the attachment
    entry, which is per session, not per call: without it an empty journal
    cannot be told apart from a hook that never started."""
    _cli(tmp_path, "init")
    before = len(Indenture(tmp_path / ".indenture").entries())
    for _ in range(4):
        _hook(tmp_path, "ls -la", session="s-quiet")
    after = len(Indenture(tmp_path / ".indenture").entries())
    assert after == before + 1


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


# --------------------------------------------------------------------------- #
# Concurrency — the failure that matters most, since concurrent agents are the
# headline use case
# --------------------------------------------------------------------------- #
def test_this_platform_has_a_locking_primitive() -> None:
    """Not a tautology: it is the precondition for the test below to mean
    anything. If this fails, the suite is proving nothing about concurrency."""
    import indenture as ind_mod  # noqa: PLC0415

    assert ind_mod.LOCKING in {"fcntl", "msvcrt"}


def test_concurrent_writers_do_not_fork_the_chain(tmp_path: Path) -> None:
    """Without the lock this reliably produces duplicate seq values: twenty-four
    writers measured eight distinct sequence numbers and twenty-five chain
    problems. The read-tip-then-append window has to be indivisible."""
    _cli(tmp_path, "init")
    root = tmp_path / ".indenture"
    writers = 16

    script = (
        "import sys; sys.path.insert(0, %r);"
        "from indenture import Indenture;"
        "Indenture(%r).write_state('k'+sys.argv[1], {'v': 1}, by='data')"
        % (str(HERE), str(root))
    )
    procs = [
        subprocess.Popen([sys.executable, "-c", script, str(n)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for n in range(writers)
    ]
    for p in procs:
        assert p.wait(timeout=60) == 0, p.stderr.read().decode()

    entries = Indenture(root).entries()
    seqs = [e["seq"] for e in entries]
    assert len(entries) == writers, f"{len(entries)} entries for {writers} writers"
    assert len(set(seqs)) == writers, f"duplicate seq: {sorted(seqs)}"
    assert sorted(seqs) == list(range(writers))

    ok, problems = Indenture(root).verify()
    assert ok, problems


def test_absent_locking_warns_once_and_still_records(tmp_path: Path, capsys) -> None:
    """Refusing to write would be the worse failure: a journal that declines to
    record is a hole in the audit trail. Same rule as an unknown actor on a
    state write."""
    import indenture as ind_mod  # noqa: PLC0415

    saved, ind_mod.LOCKING = ind_mod.LOCKING, None
    ind_mod.Indenture._warned_unlocked = False
    try:
        ind = ind_mod.Indenture(tmp_path / ".indenture")
        ind.init()
        ind.note("one")
        ind.note("two")
        warnings = [l for l in capsys.readouterr().err.splitlines() if "locking" in l]
        assert len(warnings) == 1, warnings
        assert len(ind.entries()) == 2
    finally:
        ind_mod.LOCKING = saved
        ind_mod.Indenture._warned_unlocked = False


def test_hook_takes_the_actor_from_argv(tmp_path: Path) -> None:
    """One settings.json has to work on Windows and Unix, so the actor cannot
    arrive through `VAR=value command` — that is Unix shell syntax only."""
    _cli(tmp_path, "init")
    r = _hook(tmp_path, "kubectl apply -f prod.yaml", actor="backend", by_argv=True)
    assert r.returncode == 2
    assert "backend -> deploy" in r.stderr


def test_env_overrides_argv(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    argv = [sys.executable, str(HERE / "examples" / "claude_code_hook.py"), "ghost"]
    r = subprocess.run(
        argv, input=json.dumps({"tool_name": "Bash",
                                "tool_input": {"command": "kubectl apply -f x.yaml"}}),
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "INDENTURE_ACTOR": "backend",
             "INDENTURE_DIR": str(tmp_path / ".indenture")},
    )
    assert "backend -> deploy" in r.stderr, r.stderr


def test_no_actor_anywhere_is_unknown_and_refused(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    r = subprocess.run(
        [sys.executable, str(HERE / "examples" / "claude_code_hook.py")],
        input=json.dumps({"tool_name": "Bash",
                          "tool_input": {"command": "kubectl apply -f x.yaml"}}),
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "INDENTURE_DIR": str(tmp_path / ".indenture")},
    )
    assert r.returncode == 2
    assert "unknown" in r.stderr


def test_package_release_is_refused_but_git_push_is_not(tmp_path: Path) -> None:
    """A published package cannot be unpublished after 72 hours; a pushed commit
    is undone by a revert. Same actor, same target, different blast radius —
    which is what `kind` exists to express."""
    root = tmp_path / ".indenture"
    root.mkdir()
    (root / "policy.json").write_text(
        (HERE / "examples" / "policy-claude-code.json").read_text())
    (root / "journal.jsonl").touch()
    assert _hook(tmp_path, "git push origin main", actor="claude", by_argv=True).returncode == 0
    r = _hook(tmp_path, "npm publish", actor="claude", by_argv=True)
    assert r.returncode == 2
    assert "72 hours" in r.stderr


# --------------------------------------------------------------------------- #
# doctor — exists because a hook that cannot start is a gate that silently
# disappeared, and nothing is written to say so
# --------------------------------------------------------------------------- #
def test_doctor_is_healthy_after_init(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    r = _cli(tmp_path, "doctor")
    assert r.returncode == 0, r.stdout
    assert "healthy" in r.stdout
    assert "locking" in r.stdout


def test_doctor_fails_without_a_policy(tmp_path: Path) -> None:
    r = _cli(tmp_path, "doctor")
    assert r.returncode == EXIT_LEDGER
    assert "no policy" in r.stdout


def test_doctor_flags_a_permissive_default(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    pol = tmp_path / ".indenture" / "policy.json"
    cfg = json.loads(pol.read_text())
    cfg["default"] = "allow"
    pol.write_text(json.dumps(cfg))
    r = _cli(tmp_path, "doctor")
    assert r.returncode == EXIT_LEDGER
    assert "not 'deny'" in r.stdout


def test_doctor_flags_a_broken_existing_journal(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    _cli(tmp_path, "note", "one")
    journal = tmp_path / ".indenture" / "journal.jsonl"
    journal.write_text(journal.read_text().replace("one", "tampered"))
    r = _cli(tmp_path, "doctor")
    assert r.returncode == EXIT_LEDGER
    assert "does not verify" in r.stdout


def test_doctor_does_not_write_to_the_real_journal(tmp_path: Path) -> None:
    """A health check that pollutes the thing it checks is not a health check."""
    _cli(tmp_path, "init")
    _cli(tmp_path, "note", "real")
    before = len(Indenture(tmp_path / ".indenture").entries())
    _cli(tmp_path, "doctor")
    assert len(Indenture(tmp_path / ".indenture").entries()) == before


@pytest.mark.parametrize("command", [
    "vercel --prod",
    "netlify deploy --prod",
    "firebase deploy",
    "wrangler deploy",
])
def test_front_end_deploys_are_watched(tmp_path: Path, command: str) -> None:
    """The first watched list was backend-shaped: kubectl, terraform, helm —
    none of which appear in a Vite repository, where `vercel --prod` is the
    irreversible command."""
    _cli(tmp_path, "init")
    assert _hook(tmp_path, command, actor="backend", by_argv=True).returncode == 2, command


# --------------------------------------------------------------------------- #
# attachment — a quiet journal must not be mistaken for a quiet agent
# --------------------------------------------------------------------------- #
def _notes(tmp_path: Path) -> list:
    return [e for e in Indenture(tmp_path / ".indenture").entries()
            if e.get("event") == "note"
            and str(e.get("text", "")).startswith("hook attached")]


def test_the_hook_records_that_it_ran_even_on_an_unwatched_command(tmp_path: Path) -> None:
    """The case that exposed this: an agent ran greps and cats, nothing watched,
    and the empty journal was read as 'nothing happened' when it could equally
    have meant 'the hook never started'."""
    _cli(tmp_path, "init")
    r = _hook(tmp_path, "ls -la")
    assert r.returncode == 0
    assert len(_notes(tmp_path)) == 1


def test_attachment_is_recorded_once_per_session(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    for _ in range(5):
        _hook(tmp_path, "echo hello", session="s-same")
    assert len(_notes(tmp_path)) == 1


def test_a_new_session_records_again(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    _hook(tmp_path, "echo hello", session="s-one")
    _hook(tmp_path, "echo hello", session="s-two")
    assert len(_notes(tmp_path)) == 2


def test_attachment_does_not_change_the_verdict(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    assert _hook(tmp_path, "kubectl apply -f prod.yaml").returncode == 2
    assert _hook(tmp_path, "ls").returncode == 0


def test_doctor_says_so_when_no_hook_ever_attached(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    _cli(tmp_path, "note", "written by hand, not by a hook")
    r = _cli(tmp_path, "doctor")
    assert "never recorded attaching" in r.stdout


def test_doctor_reports_the_attachment(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    _hook(tmp_path, "ls")
    r = _cli(tmp_path, "doctor")
    assert "last attached" in r.stdout
    assert r.returncode == 0


# --------------------------------------------------------------------------- #
# the rename from `custody` to `indenture` broke two strings
# --------------------------------------------------------------------------- #
def test_the_tool_describes_itself_as_chain_of_custody(tmp_path: Path) -> None:
    """`chain of custody` is the term of art and the whole pitch. A global
    search-and-replace of the old name turned it into `chain of indenture`,
    which means nothing — in the module docstring and in `--help`, the two
    first lines anyone reads."""
    assert "chain of custody" in HERE.joinpath("indenture.py").read_text().lower()
    assert "chain of indenture" not in HERE.joinpath("indenture.py").read_text().lower()
    r = subprocess.run([sys.executable, str(HERE / "indenture.py"), "--help"],
                       capture_output=True, text=True)
    assert "chain of custody" in r.stdout.lower()


def test_the_vendorable_file_carries_its_license(tmp_path: Path) -> None:
    """The advertised install is `curl -O indenture.py`, so the file travels on
    its own. One that arrives with no licence notice leaves whoever received it
    unable to say under what terms they hold it."""
    for name in ("indenture.py", "examples/claude_code_hook.py"):
        head = HERE.joinpath(name).read_text().split("\n")[:5]
        assert any("SPDX-License-Identifier: MIT OR Apache-2.0" in l for l in head), name
        assert any("Copyright" in l for l in head), name


# --------------------------------------------------------------------------- #
# The record protects itself — an agent that can edit the journal, the policy
# or the hook writes its own account of what it did
# --------------------------------------------------------------------------- #
def _hook_event(tmp_path: Path, tool: str, tool_input: dict,
                actor: str = "claude") -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "INDENTURE_DIR": str(tmp_path / ".indenture"),
           "CLAUDE_PROJECT_DIR": str(tmp_path)}
    return subprocess.run(
        [sys.executable, str(HERE / "examples" / "claude_code_hook.py"), actor],
        input=json.dumps({"tool_name": tool, "session_id": "s-1", "tool_input": tool_input}),
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )


def _with_claude_policy(tmp_path: Path) -> None:
    root = tmp_path / ".indenture"
    root.mkdir()
    (root / "policy.json").write_text(
        (HERE / "examples" / "policy-claude-code.json").read_text())
    (root / "journal.jsonl").touch()


@pytest.mark.parametrize("tool,key,rel", [
    ("Edit", "file_path", ".indenture/journal.jsonl"),
    ("Write", "file_path", ".indenture/policy.json"),
    ("MultiEdit", "file_path", ".claude/settings.json"),
    ("Write", "file_path", ".claude/settings.local.json"),
    ("NotebookEdit", "notebook_path", ".indenture/anything.ipynb"),
])
def test_editing_tools_cannot_touch_the_record(tmp_path: Path, tool: str, key: str,
                                               rel: str) -> None:
    _with_claude_policy(tmp_path)
    r = _hook_event(tmp_path, tool, {key: rel})
    assert r.returncode == 2, (tool, rel, r.stderr)
    assert "audit trail" in r.stderr
    assert "tamper" in r.stderr


def test_editing_tools_cannot_touch_the_hook_itself(tmp_path: Path) -> None:
    _with_claude_policy(tmp_path)
    hook = HERE / "examples" / "claude_code_hook.py"
    assert _hook_event(tmp_path, "Edit", {"file_path": str(hook)}).returncode == 2
    assert _hook_event(tmp_path, "Edit", {"file_path": str(HERE / "indenture.py")}).returncode == 2


def test_ordinary_edits_pass_and_are_not_journaled(tmp_path: Path) -> None:
    _with_claude_policy(tmp_path)
    r = _hook_event(tmp_path, "Edit", {"file_path": "src/app.py"})
    assert r.returncode == 0
    entries = list(Indenture(tmp_path / ".indenture").entries())
    assert all(e.get("kind") != "tamper" for e in entries)


@pytest.mark.parametrize("command", [
    "sed -i 1d .indenture/journal.jsonl",
    "echo '{}' >> .indenture/journal.jsonl",
    "head -n 3 .indenture/journal.jsonl > /tmp/j && mv /tmp/j .indenture/journal.jsonl",
    "rm .indenture/policy.json",
    "cp /tmp/open.json .indenture/policy.json",
    "python3 -c \"open('.indenture/journal.jsonl','w')\"",
    "sed -i 's/Bash//' .claude/settings.json",
    "indenture init --force",
    "python3 indenture.py --dir .indenture init --force",
    "indenture log > .indenture/journal.jsonl",
])
def test_the_shell_cannot_rewrite_the_record(tmp_path: Path, command: str) -> None:
    _with_claude_policy(tmp_path)
    r = _hook_event(tmp_path, "Bash", {"command": command})
    assert r.returncode == 2, (command, r.stderr)


@pytest.mark.parametrize("command", [
    "indenture log",
    "indenture verify",
    "python3 indenture.py --dir .indenture why 12",
    "indenture doctor",
    "npm test",
])
def test_reading_the_record_through_the_cli_is_allowed(tmp_path: Path, command: str) -> None:
    _with_claude_policy(tmp_path)
    assert _hook_event(tmp_path, "Bash", {"command": command}).returncode == 0, command


def test_the_tamper_refusal_is_recorded_with_its_real_reason(tmp_path: Path) -> None:
    """Same lesson as the destructive actor: the right verdict for the wrong
    reason is a lie in the journal. Tampering is refused as tampering."""
    _with_claude_policy(tmp_path)
    _hook_event(tmp_path, "Edit", {"file_path": ".indenture/journal.jsonl"})
    denied = [e for e in Indenture(tmp_path / ".indenture").entries()
              if e.get("decision") == "deny"]
    assert denied and denied[-1]["kind"] == "tamper"


def test_the_shipped_default_policy_also_names_tampering(tmp_path: Path) -> None:
    _cli(tmp_path, "init")
    r = _hook_event(tmp_path, "Write", {"file_path": ".indenture/policy.json"}, actor="backend")
    assert r.returncode == 2
    assert "audit trail" in r.stderr


def test_verify_cannot_see_a_truncated_tail(tmp_path: Path) -> None:
    """A documented limitation, pinned so it cannot be forgotten or quietly
    claimed away: dropping the last entries leaves a shorter chain that is
    still valid. Only a copy of the tip held elsewhere — the reserved `receipt`
    field — can tell. If this test ever fails, the README and SECURITY.md are
    out of date."""
    _cli(tmp_path, "init")
    for i in range(4):
        _cli(tmp_path, "note", f"n{i}")
    journal = tmp_path / ".indenture" / "journal.jsonl"
    lines = journal.read_text().splitlines(keepends=True)
    journal.write_text("".join(lines[:-2]))
    assert _cli(tmp_path, "verify").returncode == 0


# --------------------------------------------------------------------------- #
# the ANSSI mapping — a document that names a version will outlive it
# --------------------------------------------------------------------------- #
def test_the_anssi_mapping_names_the_current_version() -> None:
    """A compliance-adjacent document that claims to describe version X while the
    code is at version Y is the defect this project keeps finding: an assertion
    copied forward and never re-checked. If this fails, re-verify the mapping
    against the code before bumping the number."""
    import re
    for name in ("docs/ANSSI.md", "docs/fr/ANSSI.md"):
        text = HERE.joinpath(name).read_text(encoding="utf-8")
        claimed = set(re.findall(r"0\.\d+\.\d+", text))
        assert claimed == {__version__}, (
            f"{name} mentions {sorted(claimed)} but the code is {__version__}")


def test_the_anssi_mapping_states_the_five_gaps_and_claims_no_endorsement() -> None:
    """The useful half of that document is what the tool does NOT do, and the
    sentence that keeps it honest. Both are load-bearing: a mapping that reads as
    a compliance claim is worse than no mapping."""
    def flat(name: str) -> str:
        raw = HERE.joinpath(name).read_text(encoding="utf-8").lower()
        return " ".join(raw.split())
    en, fr = flat("docs/ANSSI.md"), flat("docs/fr/ANSSI.md")
    assert "has not reviewed this tool" in en and "does not endorse" in en
    assert "n'a pas examiné cet outil" in fr and "ne le cautionne pas" in fr
    for phrase in ("human-approval", "chain-of-actions", "no result recorded",
                   "in-run revocation", "requester authentication"):
        assert phrase in en, phrase
