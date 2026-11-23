#!/usr/bin/env python3
# Copyright 2026 Sylvain Cartier
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
Claude Code PreToolUse hook — turn the policy into enforcement.

A rule written in a prompt is a suggestion; the model can ignore it and nothing
records that it did. A rule applied by the runtime is a rule. That difference is
the whole point of this file.

Install (`.claude/settings.json`):

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
            "hooks": [
              {"type": "command",
               "command": "/usr/bin/python3 examples/claude_code_hook.py claude"}
            ]
          }
        ]
      }
    }

Give the interpreter's ABSOLUTE path, not `python`. If this hook cannot start,
Claude Code reports the failure and runs the command anyway — it fails open —
and since the thing that writes never started, the journal stays empty and says
nothing about it. On Windows `python` commonly resolves to the Microsoft Store
stub, which is not an interpreter; that is how this was discovered. Run
`indenture doctor` after wiring this up: it is the ten-second check.

The actor name is the first argument. It is passed on the command line rather
than through an environment variable because `VAR=value command` is Unix shell
syntax: on Windows it is not valid, and the same settings.json has to work on
both. `INDENTURE_ACTOR` still overrides it, for callers that prefer the
environment.

Behaviour:
  exit 0  — allowed, or the tool is not under policy. Claude Code proceeds.
  exit 2  — denied. Claude Code blocks the call and feeds stderr to the model,
            so it sees the reason rather than an opaque failure.

The file-editing tools are in the matcher for one reason: the record. An agent
that can open the journal, the policy, this hook or Claude Code's settings with
Edit or Write can rewrite the account of what it did, or switch the gate off,
without ever touching a watched command. Those paths are refused as `tamper`,
from the editing tools and from the shell alike. Every other edit passes
through unrecorded. This closes the obvious routes, not every route: a script
the agent writes and then runs can still reach the file. This is a gate, not a
sandbox — for more, make the journal unwritable by the agent's OS user, or ship
it somewhere append-only.

Tools that are not under policy are NOT journaled. A journal that records every
unmonitored call is a journal nobody reads, and the signal disappears into it.
The one exception is a single `hook attached` note per session, so that a quiet
journal can be told apart from a hook that never started. It keeps the session
id in `.indenture/hook-session`; that file is local state, not part of the
record — gitignore it.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# Both layouts have to work: this file inside the repo (indenture.py one level
# up), and this file vendored next to a copied indenture.py. The advertised
# install is `curl -O indenture.py`, so the vendored case is not the exotic one.
_here = Path(__file__).resolve().parent
sys.path[:0] = [str(_here), str(_here.parent)]
from indenture import Indenture  # noqa: E402

# Commands that are watched, mapped to the actor they are treated as handing
# work to. Everything else passes through unrecorded.
#
# The pattern is matched against the start of the command, anchored, so that
# `kubectl apply` matches and `echo kubectl apply` does not.
WATCHED: list[tuple[str, str, str]] = [
    (r"kubectl\s+(apply|delete|scale|rollout)\b", "deploy", "deployment"),
    (r"terraform\s+(apply|destroy)\b", "deploy", "infrastructure"),
    (r"(docker\s+push|helm\s+(install|upgrade))\b", "deploy", "deployment"),
    # Front-end deployment. The first version of this list was written with a
    # backend in mind — kubectl, terraform, helm — none of which appear in a
    # Vite or Next repository. On those, `vercel --prod` IS the irreversible
    # command, and it was missing entirely.
    (r"vercel\s+(--prod|deploy|promote)\b", "deploy", "deployment"),
    (r"netlify\s+deploy\b.*--prod\b", "deploy", "deployment"),
    (r"(firebase|wrangler|sst|amplify)\s+(deploy|publish)\b", "deploy", "deployment"),
    (r"(gh-pages|surge)\b", "deploy", "deployment"),
    (r"git\s+push\b", "deploy", "publication"),
    # A package pushed to a registry cannot be unpublished after 72 hours, so it
    # does not belong in the same bucket as `git push`, which a revert undoes.
    (r"(npm|pnpm|yarn)\s+publish\b", "deploy", "package-release"),
    # Only absolute or home-relative targets. `rm -rf node_modules` is a Tuesday;
    # `rm -rf /` and `rm -rf ~/...` are the ones worth stopping. A default that
    # blocks the former gets the whole hook uninstalled within an hour.
    (r"rm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME)", "destructive", "destructive"),
    (r"dd\s+if=", "destructive", "destructive"),
    (r"(psql|mysql|mongosh)\b", "data", "database"),
    (r"curl\b.*\|\s*(ba)?sh\b", "destructive", "remote-code"),
]


# --------------------------------------------------------------------------- #
# The record protects itself.
#
# A journal the agent can edit is a journal the agent writes. These are the
# files whose integrity the whole tool rests on: the journal and the policy
# (the indenture directory), this hook and the module it imports, and Claude
# Code's settings, where the hook is switched on. Refused as kind `tamper`, so a
# policy can give the refusal its own reason — and relax it, deliberately.
# --------------------------------------------------------------------------- #
EDIT_TOOLS = {"Edit": "file_path", "Write": "file_path",
              "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}

# Reading the journal is fine, and the CLI is how it is meant to be read. A
# read-only subcommand with no redirection or chaining is let through even when
# it names the directory; anything else that names a protected file is refused.
READ_ONLY_CLI = re.compile(
    r"(\S*python[\d.]*\s+)?\S*indenture(\.py)?\s+(--dir\s+\S+\s+)?"
    r"(log|verify|doctor|why|blame|replay)\b[^;&|>`$]*$")
# `init --force` rewrites the policy without naming any file.
REINIT = re.compile(r"(\S*python[\d.]*\s+)?\S*indenture(\.py)?\s+(--dir\s+\S+\s+)?init\b")


def protected_paths(root: Path) -> list[Path]:
    """The files and directories an agent must not edit, resolved."""
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path.cwd())
    import indenture as _module  # noqa: PLC0415 — already imported above
    return [
        root.resolve(),
        Path(__file__).resolve(),
        Path(_module.__file__).resolve(),
        (project / ".claude" / "settings.json").resolve(),
        (project / ".claude" / "settings.local.json").resolve(),
    ]


def touches_protected(path: str, root: Path) -> bool:
    """True if `path` is, or is inside, a protected file or directory."""
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path.cwd())
    p = Path(path)
    p = (p if p.is_absolute() else project / p).resolve()
    return any(p == q or q in p.parents for q in protected_paths(root))


def names_protected(command: str, root: Path) -> bool:
    """True if a shell command names a protected file in a way that could write.

    Matching on names is coarse on purpose: a shell command is not parsed here,
    and a gate that tries to tell `cat` from `cat >` by grammar is a gate with a
    hole in its grammar. Reading goes through the CLI instead.
    """
    stripped = command.strip()
    if REINIT.match(stripped):
        return True
    if READ_ONLY_CLI.match(stripped):
        return False
    names = {root.name, ".claude/settings", ".claude\\settings",
             Path(__file__).name, "indenture.py"}
    return any(n in command for n in names)


SESSION_MARKER = "hook-session"


def record_attachment(ind: Indenture, actor: str, session: str) -> None:
    """Write one entry the first time the hook runs in a session.

    Without this, a journal with nothing in it has two readings: the gate is
    watching and the agent simply did nothing watched, or the gate never
    started. Those are opposite facts and they looked identical — which is the
    same defect as the fail-open, one layer up. One entry per session makes the
    journal able to answer "was anything enforcing this?" and costs one small
    file read per hook call.
    """
    marker = ind.root / SESSION_MARKER
    try:
        if marker.exists() and marker.read_text(encoding="utf-8").strip() == session:
            return
    except OSError:
        pass
    try:
        ind.note(f"hook attached as '{actor}' (session {session[:12]}), "
                 f"{len(WATCHED)} patterns watched", by=actor)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(session, encoding="utf-8")
    except OSError:
        # Journaling the attachment is diagnostics, not the decision. Never let
        # it stop the authorization below from happening.
        pass


def classify(command: str) -> tuple[str, str] | None:
    """(target actor, kind) if this command is under policy, else None."""
    stripped = command.strip()
    for pattern, target, kind in WATCHED:
        if re.match(pattern, stripped):
            return target, kind
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        # A hook that cannot read its input must not silently allow. But it is
        # also not a policy decision, so it is not exit 2.
        print("indenture: could not parse hook input", file=sys.stderr)
        return 1

    tool = str(event.get("tool_name") or "Bash")
    tool_input = event.get("tool_input") or {}
    command = tool_input.get("command", "") if tool == "Bash" else ""
    path = tool_input.get(EDIT_TOOLS[tool], "") if tool in EDIT_TOOLS else ""
    if not command and not path:
        return 0

    # argv[1] first, so one settings.json works on Windows and Unix alike.
    actor = os.environ.get("INDENTURE_ACTOR") or (
        sys.argv[1] if len(sys.argv) > 1 else "unknown")
    root = Path(os.environ.get("INDENTURE_DIR", ".indenture"))
    ind = Indenture(root)

    # Before classifying, not after: the point is to prove the gate ran, which
    # matters most in the session where nothing watched ever happens.
    record_attachment(ind, actor, str(event.get("session_id") or "no-session-id"))

    if path:
        if not touches_protected(path, root):
            return 0
        target, kind, payload = "destructive", "tamper", {"tool": tool, "path": path}
    elif names_protected(command, root):
        target, kind, payload = "destructive", "tamper", {"command": command}
    else:
        verdict = classify(command)
        if verdict is None:
            return 0
        (target, kind), payload = verdict, {"command": command}

    decision = ind.authorize(actor, target, kind=kind, payload=payload)

    if decision.allowed:
        return 0

    # stderr is what Claude Code hands back to the model. Give it the reason and
    # what to do instead — a bare refusal just gets retried.
    print(
        f"indenture denied this call: {decision.reason}\n"
        f"  actor: {actor} -> {target}  (kind: {kind})\n"
        f"  rule: {decision.rule}  journal entry: #{decision.seq}\n"
        f"Do not retry. Ask the operator to perform it, or hand the work to an "
        f"actor the policy allows.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
