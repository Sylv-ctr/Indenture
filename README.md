# indenture

**Chain of custody for multi-agent systems.** Who was allowed to hand work to whom, what they
passed, and how to replay it from the point where they shouldn't have been.

Single file. Standard library only. Works with any agent framework, and from any language —
`indenture check` answers with an exit code.

---

## The problem

Tracing tells you what your agents did. It does not tell you what they should have been allowed
to do, and it does not help you get back.

> OpenTelemetry works for per-call latency and token counting, but breaks on coordination
> between agents — the trace shows the execution path, not whether a handoff should have been
> allowed.

> An upstream agent passes malformed state, a downstream agent takes a destructive action, and
> the root cause is three steps up the chain.

> Concurrent agents overwrite shared state: zero errors, plausible output, wrong result.

That last one is the expensive one, because it does not look like a bug. It looks like the model
got dumber, so you add more agents, and it gets worse.

## 30 seconds

```console
$ indenture init
indenture initialised in .indenture/

$ indenture check backend qa --kind review_request
ALLOW  backend -> qa [review_request]  (rules[3])
$ echo $?
0

$ indenture check backend deploy --kind work
DENY  backend -> deploy [work]  (rules[0])  irreversible lane: deployment requires an explicit human handoff
$ echo $?
2
```

Both the allow and the deny are now in the journal. **The denials are the half that tracing
throws away** — "what did this system refuse to do, and why" has no answer unless refusals are
written down.

A denial is exit **2**, never 1. Python returns 1 on an unhandled exception and argparse returns
2 on usage, so a denial sharing 1 could not be told apart from the tool crashing — and a caller
needs to fail closed on both while knowing which happened. The full table is in
[`docs/DESIGN.md`](docs/DESIGN.md).

Then somebody edits the log to cover their tracks:

```console
$ indenture verify
CHAIN BROKEN: 1 problem(s) across 9 entries
  entry 6: entry altered after writing
$ echo $?
4
```

Each entry carries the hash of the one before it. An edited entry, a deleted entry and a
reordered file are all detectable, rather than merely unlikely.

## The three verbs

**Authorize.** Default-deny policy over who may hand what to whom. First matching rule wins; if
none matches, the default decides, and the default is `deny`. An authorization layer that fails
open is decoration.

```json
{
  "default": "deny",
  "actors": { "backend": {"lane": "contained"}, "deploy": {"lane": "irreversible"} },
  "rules": [
    {"from": "*", "to": "deploy", "allow": false,
     "reason": "irreversible lane: deployment requires an explicit human handoff"},
    {"from": ["backend","frontend"], "to": ["qa","architect"],
     "kind": ["work","question","review_request"], "allow": true}
  ]
}
```

**Journal.** Append-only, hash-chained, tamper-evident. One JSON object per line, documented in
[`docs/DESIGN.md`](docs/DESIGN.md), so you can build on it without this library.

**Replay.** Fold the journal back into state at any point, ask who last wrote a key, and read the
local context around an entry.

```console
$ indenture blame contracts.md
writes to contracts.md, oldest first:
  #5  by architect (afbf9d0f3560b0fd)
  #6  by data      (c778a646489e79a6)
  #8  by backend   (531a7dc44be00ab9)

last writer: backend at entry 8

$ indenture why 8 --window 4
context around entry 8 (same actors, immediately before):
     0 ALLOW backend -> qa  [review_request]  rules[3]
     1 DENY  backend -> deploy  [work]  rules[0]  irreversible lane: ...
     4 ALLOW human -> backend  [work]  rules[1]
>    8 WRITE backend -> contracts.md  (531a7dc44be00ab9)

This is local context, not inferred causality.
```

`indenture replay --until 6` prints the state as it stood at entry 6 — the state the agent
actually saw, not the state you have now.

## Install

```bash
pip install indenture        # or: curl -O .../indenture.py  — it is one file, vendor it
```

As a library:

```python
from indenture import Indenture

ind = Indenture(".indenture")
d = ind.authorize("backend", "qa", kind="review_request", payload=work)
if not d.allowed:
    raise PermissionError(d.reason)       # already journaled as a denial

ind.write_state("contracts.md", schema, by="data")
```

From anything that can run a process:

```bash
indenture check "$FROM" "$TO" --kind "$KIND" --quiet || exit 1
```

## Wiring it into Claude Code

A `PreToolUse` hook turns the policy into enforcement rather than a request: see
[`examples/claude_code_hook.py`](examples/claude_code_hook.py). This is the part that matters
most — a rule written in a prompt is a suggestion the model can ignore, and nothing records that
it did. A denied call exits 2, Claude Code blocks it, and the reason goes back to the model.

## Why the name

A medieval indenture was a contract written twice on one sheet, then cut along a jagged line.
Each party kept a half, and fitting the two halves back together proved the document was genuine
and untampered. It is a hash chain, five centuries early.

## Design notes

**Default-deny.** The first version of this allowed by default and it was useless: every handoff
passed, so the journal recorded nothing you could not have guessed.

**Digests, not payloads.** By default an entry stores a digest of what was passed, not the thing
itself. Storing every payload is how an audit trail becomes a secrets leak and a 2 GB file. Pass
`--store` when you want the value, and list sensitive keys under `redact` in the policy — they
are replaced with `<redacted>` before anything is written.

**Unknown actors are recorded, not refused, on state writes.** A write that already happened is a
fact, and a fact you refuse to write down is a gap in the audit trail. It is flagged
`[UNKNOWN ACTOR]` in the log. Handoffs *are* refused, because those have not happened yet.

**An empty policy declares nobody.** No actor list means no actor is known, not that every actor
is fine. The opposite is a fail-open, and in a default-deny tool it would be invisible until it
mattered.

**`why` does not claim causality.** It surfaces the entries involving the same actors immediately
before the one you are looking at, which is where root causes tend to sit. Inferring more than
that would be guessing with a confident interface.

## What this is not

- **Not a tracer.** It records decisions and handoffs, not spans. Run it next to
  OpenTelemetry; they answer different questions.
- **Not an orchestrator.** It does not run your agents, schedule them, or know what a DAG is.
- **Not cryptographic attestation.** The chain is tamper-*evident*, not tamper-*proof*: someone
  who can rewrite the whole file can recompute every hash. Ship the journal somewhere append-only
  if you need more, and the chain will tell you whether what arrived matches what was written.
- **Not a sandbox.** It records that a handoff was refused; it does not stop a process that
  ignores the exit code. Pair it with a hook if you want enforcement.

## Known limitation

**Appends are not locked.** Two processes appending at the same instant can compute the same
`seq` and `prev`, which forks the chain. It fails loudly — `verify` reports it — but it does
fail, and concurrent agents are precisely this tool's use case. Until that is fixed: write from
one process, or give each actor its own journal. Discussion in
[`docs/DESIGN.md` §7](docs/DESIGN.md).

## Status

v0.1. The API may change. The journal format and the exit codes are the parts intended to stay
stable — if you build on one thing, build on those.

```bash
pip install -e ".[dev]" && pytest     # 32 tests, one per claim made above
```

## If you run more than three agents, I want to hear from you

This is the part I cannot find out by reading. There is no reliable public data on how many teams
run more than three or five code agents in production, and that number is the whole question.

So if you do: **open an issue** and say how many agents, what they hand to each other, and what
broke last. Especially what broke last. A wrong answer about my own design is worth more than a
polite one.

MIT.
