#!/usr/bin/env python3
# Copyright 2026 Sylvain Cartier
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
indenture - chain of custody for multi-agent systems.

Tracing shows you the execution path. It does not tell you whether a handoff
should have been allowed, and it does not let you replay from the point where it
should not have been. That is what this does.

Three things, and deliberately nothing else:

  AUTHORIZE   default-deny policy over who may hand work to whom, and with what.
              Every decision is journaled - the denials too, which is the half
              that tracing throws away.

  JOURNAL     append-only, hash-chained, tamper-evident. Each entry carries the
              hash of the one before it, so a deleted or edited entry is
              detectable with `indenture verify` rather than merely unlikely.

  REPLAY      fold the journal back into state at any point, ask who last wrote
              a key, and read the local context around an entry.

Single file, standard library only. Vendor it, pip-install it, or call the CLI
from a language that is not Python - `indenture check` answers with an exit code.

Known limitation, stated here rather than discovered later: appends are not
locked. Two processes appending at the same moment can compute the same `seq`
and `prev`, which forks the chain. It fails loudly - `verify` reports it - but
it does fail, and concurrent agents are precisely this tool's use case. Until
that is fixed, write from one process, or give each actor its own journal.

    python indenture.py init
    python indenture.py check backend qa --kind review_request   # exit 0, or 2 if denied
    python indenture.py log --tail 20
    python indenture.py verify
    python indenture.py blame contracts.md
    python indenture.py replay --until 42

As a library:

    from indenture import Indenture
    c = Indenture(".indenture")
    d = c.authorize("backend", "qa", kind="review_request", payload=work)
    if not d.allowed:
        raise PermissionError(d.reason)      # already journaled as a denial
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

__version__ = "0.1.3"

GENESIS = "0" * 64
JOURNAL = "journal.jsonl"
POLICY = "policy.json"
LOCKFILE = "journal.lock"


# --------------------------------------------------------------------------- #
# File locking
# --------------------------------------------------------------------------- #
# Computing the tip and appending must be one indivisible step. Two processes
# that read the tip at the same instant compute the same `seq` and the same
# `prev`, and the chain forks. Concurrent agents are this tool's whole use case,
# so this is the failure that matters most.
#
# A dedicated lock file is used rather than the journal itself, so the lock's
# lifetime does not depend on the handles used to read and write.
try:
    import fcntl

    def _lock(fh) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)

    def _unlock(fh) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    LOCKING = "fcntl"
except ImportError:  # pragma: no cover - Windows
    try:
        import msvcrt

        def _lock(fh) -> None:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)

        def _unlock(fh) -> None:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)

        LOCKING = "msvcrt"
    except ImportError:  # pragma: no cover - neither available
        def _lock(fh) -> None:
            pass

        def _unlock(fh) -> None:
            pass

        LOCKING = None

# Entry kinds. Kept small on purpose: a vocabulary that grows is a vocabulary
# nobody can write tooling against.
E_HANDOFF = "handoff"        # an actor passing work to another actor
E_STATE = "state"            # an actor writing a named piece of shared state
E_NOTE = "note"              # free-form marker (run start, human comment, ...)
E_RESULT = "result"          # the outcome of an action an earlier entry authorized

# Exit codes. The hook contract depends on these, so they are part of the public
# surface. A policy denial is 2, never 1: Python returns 1 on an unhandled
# exception and argparse returns 2 on usage, so a denial that also used 1 could
# not be told apart from the tool crashing. A caller must be able to fail closed
# on both AND know which happened.
EXIT_OK = 0
EXIT_DENIED = 2       # denied by policy; the reason is on stdout, for the model
EXIT_USAGE = 3        # malformed input or no such entry
EXIT_LEDGER = 4       # journal unreadable, or failed verification


# --------------------------------------------------------------------------- #
# Canonical encoding and hashing
# --------------------------------------------------------------------------- #
def canonical(obj: Any) -> bytes:
    """Byte-exact encoding, so two machines hash an entry identically."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(payload: Any) -> str:
    """Stable digest of a payload, used when the payload itself is not stored."""
    if payload is None:
        return ""
    return sha(canonical(payload))[:16]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
@dataclass
class Decision:
    allowed: bool
    reason: str
    rule: str = ""
    seq: int = -1

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class Policy:
    """Default-deny authorization over handoffs.

    A rule matches on `from`, `to` and `kind`, each of which may be a string, a
    list, or "*". The first matching rule decides. If none matches, `default`
    decides, and `default` is "deny" unless you deliberately say otherwise - an
    authorization layer that fails open is decoration.
    """
    actors: dict = field(default_factory=dict)
    rules: list = field(default_factory=list)
    default: str = "deny"
    redact: list = field(default_factory=list)

    @staticmethod
    def load(path: Path) -> "Policy":
        if not path.exists():
            return Policy()
        raw = json.loads(path.read_text())
        return Policy(
            actors=raw.get("actors", {}),
            rules=raw.get("rules", []),
            default=str(raw.get("default", "deny")).lower(),
            redact=raw.get("redact", []),
        )

    @staticmethod
    def _matches(pattern: Any, value: str) -> bool:
        if pattern in ("*", None):
            return True
        if isinstance(pattern, str):
            return pattern == value
        return value in pattern

    def decide(self, src: str, dst: str, kind: str) -> Decision:
        for i, rule in enumerate(self.rules):
            if not self._matches(rule.get("from"), src):
                continue
            if not self._matches(rule.get("to"), dst):
                continue
            if not self._matches(rule.get("kind", "*"), kind):
                continue
            allow = bool(rule.get("allow", False))
            reason = rule.get("reason") or (
                f"rule {i} allows {src} -> {dst} ({kind})" if allow
                else f"rule {i} denies {src} -> {dst} ({kind})")
            return Decision(allow, reason, rule=f"rules[{i}]")
        allowed = self.default == "allow"
        return Decision(
            allowed,
            f"no rule matched {src} -> {dst} ({kind}); default is {self.default}",
            rule="default",
        )

    def lane(self, actor: str) -> str:
        return str(self.actors.get(actor, {}).get("lane", "unknown"))

    def known(self, actor: str) -> bool:
        """Declared in the policy, or not.

        An empty policy means NOBODY is declared, not everybody. Treating an
        absent actor list as "all actors are fine" is a fail-open in a tool
        whose whole premise is default-deny, and it is the kind of default that
        is invisible until it matters.
        """
        return actor in self.actors


# --------------------------------------------------------------------------- #
# The journal
# --------------------------------------------------------------------------- #
class Indenture:
    _warned_unlocked = False

    def __init__(self, root: str | Path = ".indenture") -> None:
        self.root = Path(root)
        self.journal = self.root / JOURNAL
        self.policy = Policy.load(self.root / POLICY)

    # -- setup ------------------------------------------------------------- #
    def init(self, force: bool = False) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        pol = self.root / POLICY
        if force or not pol.exists():
            pol.write_text(json.dumps(EXAMPLE_POLICY, indent=2) + "\n")
        self.journal.touch(exist_ok=True)
        self.policy = Policy.load(pol)
        return self.root

    # -- reading ----------------------------------------------------------- #
    def entries(self) -> list:
        if not self.journal.exists():
            return []
        out = []
        for line in self.journal.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"seq": -1, "event": "corrupt", "raw": line[:200]})
        return out

    def _tip(self) -> tuple:
        entries = self.entries()
        if not entries:
            return 0, GENESIS
        last = entries[-1]
        return int(last.get("seq", len(entries) - 1)) + 1, str(last.get("hash", GENESIS))

    # -- writing ----------------------------------------------------------- #
    @contextlib.contextmanager
    def _exclusive(self):
        """Serialise read-tip-then-append across processes.

        When no locking primitive exists, this warns once and proceeds. Refusing
        to write would be the worse failure: a journal that declines to record
        is a hole in the audit trail, which is the same reason an unknown actor
        is recorded rather than refused on a state write. `verify` still detects
        a chain that forked, so the failure stays loud.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        if LOCKING is None:
            if not Indenture._warned_unlocked:
                Indenture._warned_unlocked = True
                print("indenture: no file locking on this platform; concurrent "
                      "writers may fork the chain. Run `indenture verify`.",
                      file=sys.stderr)
            yield
            return
        with (self.root / LOCKFILE).open("a+", encoding="utf-8") as fh:
            _lock(fh)
            try:
                yield
            finally:
                with contextlib.suppress(OSError):
                    _unlock(fh)

    def _append(self, body: dict) -> dict:
        with self._exclusive():
            seq, prev = self._tip()
            entry = {"seq": seq, "ts": now(), "prev": prev, **body}
            entry["hash"] = sha(canonical(entry))
            with self.journal.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
        return entry

    def _payload_fields(self, payload: Any, store: bool) -> dict:
        """Digest always; the payload itself only when asked.

        Storing every payload by default is how an audit trail becomes a secrets
        leak and a 2 GB file. The digest is enough to prove what was passed.
        """
        fields = {"payload_digest": digest_of(payload)}
        if store and payload is not None:
            redacted = payload
            if isinstance(payload, dict) and self.policy.redact:
                redacted = {k: ("<redacted>" if k in self.policy.redact else v)
                            for k, v in payload.items()}
            fields["payload"] = redacted
        return fields

    # -- the three verbs --------------------------------------------------- #
    def authorize(self, src: str, dst: str, kind: str = "work",
                  payload: Any = None, store_payload: bool = False,
                  run: str = "", ref: str = "") -> Decision:
        """Decide whether src may hand `kind` to dst, and journal the decision.

        Denials are journaled too. The question "what did this system refuse to
        do, and why" has no answer unless the refusals are written down.
        """
        d = self.policy.decide(src, dst, kind)
        unknown = [a for a in (src, dst) if not self.policy.known(a)]
        if unknown and d.allowed:
            d = Decision(False, f"unknown actor(s): {', '.join(unknown)}", rule="unknown-actor")
        entry = self._append({
            "event": E_HANDOFF,
            "decision": "allow" if d.allowed else "deny",
            "from": src, "to": dst, "kind": kind,
            "from_lane": self.policy.lane(src), "to_lane": self.policy.lane(dst),
            "rule": d.rule, "reason": d.reason, "run": run, "ref": ref,
            **self._payload_fields(payload, store_payload),
        })
        d.seq = entry["seq"]
        return d

    def write_state(self, key: str, value: Any, by: str, run: str = "",
                    store_payload: bool = False) -> dict:
        """Record that `by` wrote shared state `key`. Gives replay and blame.

        This records; it does not refuse. An unknown actor is flagged on the
        entry rather than rejected, because a write that already happened is a
        fact, and a fact you refuse to write down is a gap in the audit trail.
        """
        body = {
            "event": E_STATE, "key": key, "by": by,
            "by_lane": self.policy.lane(by), "run": run,
            **self._payload_fields(value, store_payload),
        }
        if not self.policy.known(by):
            body["unknown_actor"] = True
        return self._append(body)

    def note(self, text: str, by: str = "human", run: str = "") -> dict:
        return self._append({"event": E_NOTE, "by": by, "text": text[:2000], "run": run})

    def find_by_ref(self, ref: str) -> int | None:
        """The seq of the most recent handoff carrying this correlation ref.

        A result arrives from a different process than the decision it belongs
        to, so the two are joined by a ref the host supplies - in Claude Code,
        `tool_use_id`. Most recent wins: a ref should be unique, and if it is
        not, the latest is the one being completed.
        """
        if not ref:
            return None
        found = None
        for e in self.entries():
            if e.get("event") == E_HANDOFF and e.get("ref") == ref:
                found = e.get("seq")
        return found

    def record_result(self, of: int | None, ok: bool, detail: str = "",
                      by: str = "", run: str = "") -> dict:
        """Record how an authorized action turned out.

        A separate entry, never a change to the one it refers to: the journal is
        append-only, and an entry whose bytes change is an entry whose hash
        lied. `of` is the seq of the decision; **None means the result could not
        be joined to one**, which is a fact worth writing rather than a reason
        to drop the entry.

        Like `write_state`, this records and does not refuse. The action has
        already happened; refusing to write it down would only remove evidence.

        **What the absence of a result entry does NOT mean.** It does not mean
        the action failed. The host decides whether to call us afterwards at
        all: Claude Code's PostToolUse fires after a tool *succeeds*, so a
        failure may produce nothing, and an older host, a missing hook or a dead
        interpreter also produce nothing. An entry with no result means the
        outcome was **not recorded** - see `docs/DESIGN.md` §3.4 for the same
        rule applied to `principal` and `receipt`.
        """
        body = {"event": E_RESULT, "of": of, "ok": bool(ok),
                "detail": str(detail)[:500], "by": by, "run": run}
        if of is None:
            body["uncorrelated"] = True
        return self._append(body)

    # -- integrity --------------------------------------------------------- #
    def verify(self) -> tuple:
        """Recompute the chain. Returns (ok, problems).

        Catches an edited entry, a deleted entry, and a reordered file - the
        three ways an append-only log quietly stops being one.
        """
        problems, prev = [], GENESIS
        for i, e in enumerate(self.entries()):
            if e.get("event") == "corrupt":
                problems.append((i, "unparseable line"))
                continue
            stated = e.get("hash", "")
            recomputed = sha(canonical({k: v for k, v in e.items() if k != "hash"}))
            if stated != recomputed:
                problems.append((e.get("seq", i), "entry altered after writing"))
            if e.get("prev") != prev:
                problems.append((e.get("seq", i), "broken link to previous entry"))
            if e.get("seq") != i:
                problems.append((e.get("seq", i), f"sequence gap: expected {i}"))
            prev = stated
        return (not problems), problems

    # -- replay ------------------------------------------------------------ #
    def replay(self, until: int | None = None) -> dict:
        """Fold state writes back into the state as of `until` (inclusive)."""
        state = {}
        for e in self.entries():
            if until is not None and int(e.get("seq", -1)) > until:
                break
            if e.get("event") != E_STATE:
                continue
            state[e["key"]] = {
                "digest": e.get("payload_digest", ""),
                "by": e.get("by", ""),
                "seq": e.get("seq"),
                "ts": e.get("ts"),
                "value": e.get("payload", "<not stored>"),
            }
        return state

    def blame(self, key: str) -> list:
        """Every write to a key, newest last. Provenance for a bad value."""
        return [e for e in self.entries()
                if e.get("event") == E_STATE and e.get("key") == key]

    def why(self, seq: int, window: int = 6) -> list:
        """The local context around an entry: what its actors did just before.

        Honest about its limits: this does not infer causality. It surfaces the
        entries involving the same actors immediately before the one you are
        looking at, which is where root causes tend to sit.
        """
        entries = self.entries()
        target = next((e for e in entries if int(e.get("seq", -1)) == seq), None)
        if not target:
            return []
        actors = {target.get("from"), target.get("to"), target.get("by")} - {None}
        before = [e for e in entries if int(e.get("seq", -1)) < seq
                  and ({e.get("from"), e.get("to"), e.get("by")} & actors)]
        return before[-window:] + [target]

    def denials(self) -> list:
        return [e for e in self.entries()
                if e.get("event") == E_HANDOFF and e.get("decision") == "deny"]


EXAMPLE_POLICY = {
    "_comment": "Default-deny. The first matching rule wins. 'from', 'to' and "
                "'kind' each take a string, a list, or '*'.",
    "default": "deny",
    "redact": ["api_key", "token", "password", "authorization"],
    "actors": {
        "architect": {"lane": "contained"},
        "backend": {"lane": "contained"},
        "frontend": {"lane": "contained"},
        "data": {"lane": "wide"},
        "infra": {"lane": "wide"},
        "qa": {"lane": "contained"},
        "security": {"lane": "contained"},
        "deploy": {"lane": "irreversible"},
        "destructive": {"lane": "irreversible"},
        "human": {"lane": "irreversible"},
    },
    "rules": [
        {"from": "*", "to": "deploy", "allow": False,
         "reason": "deployment is irreversible: ask the operator to run it"},
        {"from": "*", "to": "destructive", "kind": "tamper", "allow": False,
         "reason": "the journal, the policy and the hook are the audit trail: an agent "
                   "does not edit its own. Read it with `indenture log`; ask the operator "
                   "to change the policy"},
        {"from": "*", "to": "destructive", "allow": False,
         "reason": "this destroys data and cannot be undone: ask the operator to run it"},
        {"from": "human", "to": "*", "allow": True,
         "reason": "the operator may hand work to anyone"},
        {"from": "qa", "to": "*", "kind": ["rework", "verdict"], "allow": True,
         "reason": "the gate may return work to any implementer"},
        {"from": ["backend", "frontend", "data"], "to": ["qa", "architect"],
         "kind": ["work", "question", "review_request"], "allow": True},
        {"from": "architect", "to": "*", "kind": ["plan", "contract"], "allow": True},
    ],
}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _c(entry: dict) -> str:
    ev = entry.get("event")
    seq = entry.get("seq")
    ts = str(entry.get("ts", ""))[11:19]
    if ev == E_HANDOFF:
        mark = "ALLOW" if entry.get("decision") == "allow" else "DENY "
        return (f"{seq:>4} {ts} {mark} {entry.get('from','?')} -> {entry.get('to','?')}"
                f"  [{entry.get('kind','')}]  {entry.get('rule','')}"
                + (f"  {entry.get('reason','')}" if entry.get("decision") == "deny" else ""))
    if ev == E_STATE:
        flag = "  [UNKNOWN ACTOR]" if entry.get("unknown_actor") else ""
        return (f"{seq:>4} {ts} WRITE {entry.get('by','?')} -> {entry.get('key','?')}"
                f"  ({entry.get('payload_digest','')}){flag}")
    if ev == E_NOTE:
        return f"{seq:>4} {ts} NOTE  {entry.get('by','?')}: {entry.get('text','')[:90]}"
    if ev == E_RESULT:
        of = entry.get("of")
        target = f"#{of}" if of is not None else "[UNCORRELATED]"
        mark = "OK   " if entry.get("ok") else "FAIL "
        return (f"{seq:>4} {ts} {mark} result of {target}"
                + (f"  {entry.get('detail','')[:80]}" if entry.get("detail") else ""))
    return f"{seq:>4} {ts} {ev}"


def _doctor(root: str) -> int:
    """Prove the installation works, rather than assuming it does.

    This exists because of a real failure: on Windows, `python` resolved to the
    Microsoft Store stub, the hook could not start, and the host ran the command
    anyway. A hook that cannot start is not a refusal — it is a gate that
    silently disappeared, and nothing was written, so nothing said so. One
    command that exits 0 or tells you why is the cheapest defence against that.
    """
    import platform
    import tempfile

    problems: list = []
    print(f"python      {sys.version.split()[0]} on {platform.system()} "
          f"({platform.machine()})")
    print(f"executable  {sys.executable}")
    print(f"indenture   {__version__} from {Path(__file__).resolve()}")

    if LOCKING:
        print(f"locking     {LOCKING}")
    else:
        print("locking     NONE — concurrent writers may fork the chain")
        problems.append("no locking primitive on this platform")

    ind = Indenture(root)
    pol = ind.root / POLICY
    if not pol.exists():
        print(f"policy      MISSING at {pol} — run `indenture init`")
        problems.append("no policy")
    else:
        try:
            Policy.load(pol)
            p = ind.policy
            print(f"policy      {pol}  ({len(p.actors)} actors, {len(p.rules)} rules, "
                  f"default={p.default})")
            if p.default != "deny":
                problems.append(f"default is {p.default!r}, not 'deny'")
            if not p.actors:
                problems.append("no actors declared: every handoff will be refused")
        except Exception as exc:
            print(f"policy      UNREADABLE: {exc}")
            problems.append("policy does not parse")

    # Can we actually write and verify a chain? Done in a throwaway directory so
    # the real journal is not polluted by a health check.
    with tempfile.TemporaryDirectory() as tmp:
        try:
            probe = Indenture(Path(tmp) / ".indenture")
            probe.root.mkdir(parents=True, exist_ok=True)
            probe.note("doctor self-test", by="doctor")
            probe.note("doctor self-test", by="doctor")
            ok, why = probe.verify()
            print(f"write+chain {'ok' if ok else 'BROKEN: ' + str(why)}")
            if not ok:
                problems.append("cannot write a verifiable chain")
        except Exception as exc:
            print(f"write+chain FAILED: {exc}")
            problems.append(f"cannot write: {exc}")

    if ind.journal.exists():
        n = len(ind.entries())
        ok, why = ind.verify()
        print(f"journal     {ind.journal}  ({n} "
              f"{'entry' if n == 1 else 'entries'}, "
              f"{'intact' if ok else str(len(why)) + ' problems'})")
        if not ok:
            problems.append("the existing journal does not verify")
        attached = [e for e in ind.entries()
                    if e.get("event") == E_NOTE
                    and str(e.get("text", "")).startswith("hook attached")]
        if attached:
            last = attached[-1]
            print(f"hook        last attached {last.get('ts')} — {last.get('text')}")
        else:
            print("hook        never recorded attaching. Either no hook is wired, or")
            print("            it is not the bundled one. An empty or quiet journal")
            print("            proves nothing about whether anything is enforcing.")
    else:
        print(f"journal     none yet at {ind.journal}")
        print("            If a hook is wired and you have run commands, an empty")
        print("            journal means the hook never started. Check the host's")
        print("            hook log: a hook that fails may not block anything.")

    print()
    if problems:
        print(f"NOT HEALTHY: {len(problems)} problem(s)")
        for pb in problems:
            print(f"  - {pb}")
        return EXIT_LEDGER
    print("healthy")
    return EXIT_OK


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="indenture",
        description="Chain of custody for multi-agent systems: who was allowed "
                    "to hand off to whom, what they passed, and how to replay it.")
    p.add_argument("--dir", default=os.environ.get("INDENTURE_DIR", ".indenture"),
                   help="journal directory (default: .indenture)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create the journal and an example policy")
    s.add_argument("--force", action="store_true", help="overwrite an existing policy")

    s = sub.add_parser("check", help="authorize a handoff; exit 0 if allowed, 2 if denied")
    s.add_argument("src"); s.add_argument("dst")
    s.add_argument("--kind", default="work")
    s.add_argument("--payload", default="", help="JSON string, or @file")
    s.add_argument("--store", action="store_true", help="store the payload, not just its digest")
    s.add_argument("--run", default="")
    s.add_argument("--ref", default="",
                   help="correlation id, so a later `result` can be joined to this decision")
    s.add_argument("--quiet", action="store_true")

    s = sub.add_parser("write", help="record a write to shared state")
    s.add_argument("key"); s.add_argument("--by", required=True)
    s.add_argument("--value", default=""); s.add_argument("--store", action="store_true")
    s.add_argument("--run", default="")

    s = sub.add_parser("result", help="record how an authorized action turned out")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--of", type=int, help="seq of the decision this completes")
    g.add_argument("--ref", help="correlation id of the decision this completes")
    s.add_argument("--failed", action="store_true", help="the action did not succeed")
    s.add_argument("--detail", default="")
    s.add_argument("--by", default="")
    s.add_argument("--run", default="")

    s = sub.add_parser("note", help="append a free-form marker")
    s.add_argument("text"); s.add_argument("--by", default="human")

    s = sub.add_parser("log", help="print the journal")
    s.add_argument("--tail", type=int, default=0)
    s.add_argument("--denied", action="store_true", help="only refused handoffs")
    s.add_argument("--json", action="store_true")

    sub.add_parser("verify", help="recompute the hash chain; exit 4 if broken")

    sub.add_parser("doctor", help="check that this installation actually works")

    s = sub.add_parser("replay", help="state as of an entry")
    s.add_argument("--until", type=int, default=None)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("blame", help="every write to a state key")
    s.add_argument("key")

    s = sub.add_parser("why", help="local context around an entry")
    s.add_argument("seq", type=int)
    s.add_argument("--window", type=int, default=6)

    a = p.parse_args(argv)
    c = Indenture(a.dir)

    def payload_of(raw: str) -> Any:
        if not raw:
            return None
        if raw.startswith("@"):
            raw = Path(raw[1:]).read_text()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    if a.cmd == "init":
        root = c.init(force=a.force)
        print(f"indenture initialised in {root}/")
        print(f"  policy  : {root/POLICY}  (default-deny; edit before relying on it)")
        print(f"  journal : {root/JOURNAL}")
        return 0

    if a.cmd == "check":
        d = c.authorize(a.src, a.dst, a.kind, payload_of(a.payload),
                        store_payload=a.store, run=a.run, ref=a.ref)
        if not a.quiet:
            print(f"{'ALLOW' if d.allowed else 'DENY'}  {a.src} -> {a.dst} [{a.kind}]"
                  f"  ({d.rule})  {d.reason}")
        return 0 if d.allowed else EXIT_DENIED

    if a.cmd == "write":
        e = c.write_state(a.key, payload_of(a.value), by=a.by,
                          run=a.run, store_payload=a.store)
        print(f"recorded #{e['seq']} {a.by} -> {a.key} ({e['payload_digest']})")
        return 0

    if a.cmd == "result":
        of = a.of if a.of is not None else c.find_by_ref(a.ref)
        e = c.record_result(of, ok=not a.failed, detail=a.detail, by=a.by, run=a.run)
        where = f"#{of}" if of is not None else "no matching decision"
        print(f"recorded #{e['seq']} result of {where}"
              f"  ({'ok' if not a.failed else 'failed'})")
        return 0

    if a.cmd == "note":
        e = c.note(a.text, by=a.by)
        print(f"recorded #{e['seq']}")
        return 0

    if a.cmd == "log":
        entries = c.denials() if a.denied else c.entries()
        if a.tail:
            entries = entries[-a.tail:]
        if a.json:
            print(json.dumps(entries, indent=2, ensure_ascii=False))
        elif not entries:
            print("(journal empty)")
        else:
            for e in entries:
                print(_c(e))
        return 0

    if a.cmd == "doctor":
        return _doctor(a.dir)

    if a.cmd == "verify":
        ok, problems = c.verify()
        n = len(c.entries())
        if ok:
            print(f"chain intact: {n} entries, unbroken from genesis")
            return 0
        print(f"CHAIN BROKEN: {len(problems)} problem(s) across {n} entries")
        for seq, what in problems:
            print(f"  entry {seq}: {what}")
        return EXIT_LEDGER

    if a.cmd == "replay":
        state = c.replay(a.until)
        if a.json:
            print(json.dumps(state, indent=2, ensure_ascii=False))
            return 0
        if not state:
            print("(no state recorded)")
            return 0
        where = "latest" if a.until is None else f"entry {a.until}"
        print(f"state as of {where}:")
        for k, v in state.items():
            print(f"  {k:<28} {v['digest']:<18} by {v['by']} (#{v['seq']})")
        return 0

    if a.cmd == "blame":
        rows = c.blame(a.key)
        if not rows:
            print(f"(no writes recorded for {a.key})")
            return 0
        print(f"writes to {a.key}, oldest first:")
        for e in rows:
            print(f"  #{e['seq']} {e['ts']} by {e['by']} ({e.get('payload_digest','')})")
        print(f"\nlast writer: {rows[-1]['by']} at entry {rows[-1]['seq']}")
        return 0

    if a.cmd == "why":
        rows = c.why(a.seq, a.window)
        if not rows:
            print(f"(no entry {a.seq})")
            return EXIT_USAGE
        print(f"context around entry {a.seq} (same actors, immediately before):")
        for e in rows:
            print(("> " if int(e.get("seq", -1)) == a.seq else "  ") + _c(e))
        print("\nThis is local context, not inferred causality.")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
