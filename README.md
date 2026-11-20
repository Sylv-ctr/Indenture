# indenture

**Chain of custody for multi-agent systems.**

Run a handful of AI agents that pass work to each other and you will eventually have a bad day:
one agent hands the next something malformed, the next one does something destructive with it,
and by the time anybody notices, the cause is three steps back. Indenture is what you ask
*before* each handoff. It keeps a small rulebook — which agent may pass what to whom, and what
nobody may touch without a human — and it answers yes or no. A "no" is enforced rather than
suggested: the call does not run, and the agent is told why. Every answer is written down,
refusals included, which is the half a log file never has: *what did my agents try to do that I
did not want them to?*

The other half is being able to go back. Entries are written once and never edited, and each one
carries a fingerprint of the entry before it, so a journal that was altered after the fact says
so instead of looking fine. That is what makes the record worth reading a week later: you can ask
who last wrote a given file, and see the state of the world as it stood when an agent made a bad
call — not the state now, after six more agents have run over it.

**Concretely.** Your `backend` agent finishes some code and tries `kubectl apply`. A log would
record that it did, and you would find out when production went down. Here the hook asks first,
the rulebook says deployment is irreversible and needs a human, the command never runs, and the
refusal is on the record. A week later your tests go red: `indenture blame contracts.md` says the
`data` agent wrote that file and `backend` overwrote it four steps later, and `indenture replay
--until 6` shows you what `qa` was looking at when it signed off.

It is for anyone running more than two or three agents on real work — your own orchestrator,
Claude Code subagents, CrewAI, LangGraph, a pile of shell scripts. One file, standard library
only, nothing to deploy. `indenture check` answers with an exit code, so it works from any
language.

---

## The problem, in the words of people who have it

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

## Writing the rulebook

`indenture init` writes a starting policy to `.indenture/policy.json`. Edit it — it is the only
configuration there is.

```json
{
  "default": "deny",
  "redact": ["api_key", "token", "password", "authorization"],
  "actors": {
    "architect": {"lane": "contained"},
    "backend":   {"lane": "contained"},
    "data":      {"lane": "wide"},
    "qa":        {"lane": "contained"},
    "deploy":    {"lane": "irreversible"}
  },
  "rules": [
    {"from": "*", "to": "deploy", "allow": false,
     "reason": "deployment is irreversible: ask the operator to run it"},
    {"from": "architect", "to": "*", "kind": ["plan", "contract"], "allow": true},
    {"from": ["backend", "data"], "to": "qa",
     "kind": ["work", "review_request"], "allow": true}
  ]
}
```

**`actors`** — every agent that exists, under the name you call it by. An agent missing from this
list is *unknown*: its handoffs are refused and its state writes are recorded with a flag.
Listing nobody means nobody is known, not everybody.

**`lane`** — how far that actor's mistakes reach. `contained` stays inside its own workspace,
`wide` is visible outside but can be undone, `irreversible` cannot. The lane is recorded on every
entry, and it is what you point at when you write the rule that refuses deployment. Nothing opens
the irreversible lane on its own.

**`rules`** — read top to bottom, and **the first rule that matches decides**. That is the whole
mechanism, so put your refusals first: a permissive rule sitting above a restrictive one wins
silently, and you will not notice until something ships.

Each rule matches on `from`, `to` and `kind`. Each of the three takes a single name, a list of
names, or `"*"` for any. An absent `kind` means any kind. A rule without `"allow": true`
**refuses** — permission is never implied by a rule merely existing.

**`kind`** — your own vocabulary for what is being handed over: `work`, `review_request`, `plan`,
`rework`, whatever your agents actually do. Indenture never interprets it, it only matches on it.

**`reason`** — this string is handed back to the agent when it is refused, so write it as an
instruction to the agent, not as a note to yourself. *"deployment is irreversible: ask the
operator to run it"* gives the model a next step. *"not allowed"* gives it a retry loop.

**`default`** — what happens when no rule matches. It is `deny`, and there is deliberately no
flag to invert it. If you want to be permissive, write an explicit last rule that says so, where
the next person to read the file can see it.

**`redact`** — keys replaced with `<redacted>` before anything is written, for the cases where
you do ask Indenture to store a payload instead of only its fingerprint.

### Start small

Three actors and two rules is already a working policy. Add a rule the first time a handoff is
refused that you actually wanted: the refusal is in the journal with both actors and the kind, so
it tells you exactly which rule is missing.

```console
$ indenture log --denied
   1 09:16:57 DENY  backend -> deploy  [work]  rules[0]  deployment is irreversible: ask the operator to run it
   7 09:41:02 DENY  data -> qa  [schema]  default  no rule matched data -> qa (schema); default is deny
```

Entry 7 is the one to act on — `default` in the rule column means you never wrote a rule for
that pair. Entry 1 is the policy working as intended.

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

**Read this before you trust it.** The enforcement is the host's, not this tool's. Claude Code
blocks on exit 2 — but if the hook *cannot start*, it reports the failure and **runs the command
anyway**. That is fail-open, and it is not hypothetical: on the first real Windows install,
`python` resolved to the Microsoft Store stub, the hook died with "Python was not found", and the
commands ran. Nothing was written, because the thing that writes never started — so the journal
was empty and silence meant nothing. Two consequences:

- Give the interpreter's **absolute path** in `settings.json`, not `python`.
- Run `indenture doctor` after wiring it up, and again if a journal looks suspiciously quiet.
  That is the command that would have caught the above in ten seconds.

The same trap has a second floor. Unwatched commands are deliberately not journaled, so a
session where the agent only read files leaves nothing behind — and *nothing behind* is exactly
what a dead hook leaves too. So the hook writes one `hook attached` note per session, before it
classifies anything, and `doctor` reports it. An empty journal is now a statement rather than a
shrug. Add `.indenture/hook-session` to your `.gitignore`: it is local state, not record.

```console
$ indenture doctor
python      3.13.1 on Windows (AMD64)
executable  C:\Users\me\AppData\Local\Python\bin\python.exe
indenture   0.1.0 from tools/indenture/indenture.py
locking     msvcrt
policy      .indenture/policy.json  (5 actors, 9 rules, default=deny)
write+chain ok
journal     .indenture/journal.jsonl  (41 entries, intact)

healthy
```

`doctor` is read-only on your journal — the write test happens in a temporary directory — and it
exits non-zero when something is wrong, so it works in CI too.

```bash
mkdir -p .indenture && cp examples/policy-claude-code.json .indenture/policy.json
```

Then in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command",
        "command": "/usr/bin/python3 examples/claude_code_hook.py claude"}]}
    ]
  }
}
```

The actor is the argument. It is passed on the command line rather than through an environment
variable because `VAR=value command` is Unix shell syntax — on Windows it is not valid, and the
same `settings.json` has to work on both. `INDENTURE_ACTOR` still overrides it if you prefer
the environment.

[`examples/policy-claude-code.json`](examples/policy-claude-code.json) is written for one
developer and one session: the agent may `git push` — you review the diff anyway, and blocking
it would make this unusable — but not deploy, destroy, or open a database. Loosen it where it
annoys you; `indenture log --denied` tells you which rule is missing.

With no actor given at all, the actor is `unknown` and every watched command is refused. That is
the correct direction to fail, but it looks like a bug if you forget the argument.

**Windows.** Use the interpreter's full path, with forward slashes so JSON does not eat the
backslashes:

```json
"command": "C:/Users/me/AppData/Local/Python/bin/python.exe tools/indenture/indenture_hook.py claude"
```

`where python` will often hand you `...\WindowsApps\python.exe` first. That is the Microsoft Store
stub, not an interpreter; it is what caused the fail-open above. The locking uses `msvcrt`
instead of `fcntl` on this platform; the concurrency case is the thing to report if it misbehaves.

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

## Other hosts, other providers

The core knows nothing about any provider. It imports nothing outside the standard library,
makes no network call, and never talks to a model: it takes a command, reads a JSON file, and
answers with an exit code. Whether GPT, Claude or Gemini produced the command does not reach it.

What is host-specific is the *gate* — where you put it. The hook in `examples/` speaks Claude
Code's shape. Codex, Cursor and Grok Build converged on the same convention, where **exit 2
blocks**, so an adapter is mostly a different config path and a different field name in the JSON
reply. In library mode there is nothing to adapt at all: call `authorize()` from your own
orchestrator, CrewAI, LangGraph or a shell script, and the host never enters into it.

If you run one of those hosts, that adapter is the issue I would most like to receive.

One warning that generalises. Hooks fail open, and not only here: the Windows failure described
above has an analogue reported on Codex, where a `PreToolUse` denial by exit code was classified
as a hook *failure* and the command then ran. Treat the gate as the host's, verify it with
`indenture doctor`, and read the `hook attached` entry rather than trusting a quiet journal.

## What this is not

- **Not a tracer.** It records decisions and handoffs, not spans. Run it next to
  OpenTelemetry; they answer different questions.
- **Not an orchestrator.** It does not run your agents, schedule them, or know what a DAG is.
- **Not cryptographic attestation.** The chain is tamper-*evident*, not tamper-*proof*: someone
  who can rewrite the whole file can recompute every hash. Ship the journal somewhere append-only
  if you need more, and the chain will tell you whether what arrived matches what was written.
- **Not a sandbox.** It records that a handoff was refused; it does not stop a process that
  ignores the exit code. Pair it with a hook if you want enforcement — and note that the
  enforcement is then the host's: if the host runs the command when the hook fails to start, the
  gate is gone and nothing is written to say so. `indenture doctor` exists for exactly that.

## Concurrency

Appends are serialised with an exclusive file lock, because computing the tip and writing have
to be one indivisible step. Without it the damage is not subtle: twenty-four concurrent writers
measured **eight** distinct sequence numbers and twenty-five chain problems. With it, twenty-four
entries, twenty-four sequence numbers, chain intact — and the suite runs that case on every
commit.

`fcntl` on Unix, `msvcrt` on Windows. On a platform with neither, it warns once on stderr and
still records: a journal that declines to write is a hole in the audit trail, which is the same
reason an unknown actor is recorded rather than refused on a state write. `verify` still detects
a forked chain, so the failure stays loud.

Not yet solved: a journal on a network filesystem where the lock may be a silent no-op, and
writers on different machines. Both are in [`docs/DESIGN.md` §7](docs/DESIGN.md).

## Status

v0.1.1. The API may change. The journal format and the exit codes are the parts intended to stay
stable — if you build on one thing, build on those.

```bash
pip install -e ".[dev]" && pytest     # 64 tests, one per claim made above
```

## If you run more than three agents, I want to hear from you

This is the part I cannot find out by reading. There is no reliable public data on how many teams
run more than three or five code agents in production, and that number is the whole question.

So if you do: **open an issue** and say how many agents, what they hand to each other, and what
broke last. Especially what broke last. A wrong answer about my own design is worth more than a
polite one.

## License

Dual-licensed under either of

- **MIT** ([LICENSE-MIT](LICENSE-MIT)) — if you are vendoring `indenture.py` into
  your own tree, take this one; it fits in a file header.
- **Apache License 2.0** ([LICENSE-APACHE](LICENSE-APACHE)) — if you are deploying
  this as a dependency inside a company, take this one; it carries an explicit
  patent grant, which is what legal will ask for.

at your option. Contributions are accepted under the same dual terms, with no separate agreement
to sign — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, use GitHub's private
reporting rather than an issue: [SECURITY.md](SECURITY.md) says what is in scope and what is a
documented limitation.
