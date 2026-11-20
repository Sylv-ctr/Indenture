#!/usr/bin/env python3
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
            "matcher": "Bash",
            "hooks": [
              {"type": "command",
               "command": "python examples/claude_code_hook.py claude"}
            ]
          }
        ]
      }
    }

The actor name is the first argument. It is passed on the command line rather
than through an environment variable because `VAR=value command` is Unix shell
syntax: on Windows it is not valid, and the same settings.json has to work on
both. `INDENTURE_ACTOR` still overrides it, for callers that prefer the
environment.

Behaviour:
  exit 0  — allowed, or the tool is not under policy. Claude Code proceeds.
  exit 2  — denied. Claude Code blocks the call and feeds stderr to the model,
            so it sees the reason rather than an opaque failure.

Tools that are not under policy are NOT journaled. A journal that records every
unmonitored call is a journal nobody reads, and the signal disappears into it.
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

    command = (event.get("tool_input") or {}).get("command", "")
    if not command:
        return 0

    verdict = classify(command)
    if verdict is None:
        return 0

    target, kind = verdict
    # argv[1] first, so one settings.json works on Windows and Unix alike.
    actor = os.environ.get("INDENTURE_ACTOR") or (
        sys.argv[1] if len(sys.argv) > 1 else "unknown")

    ind = Indenture(os.environ.get("INDENTURE_DIR", ".indenture"))
    decision = ind.authorize(actor, target, kind=kind, payload={"command": command})

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
