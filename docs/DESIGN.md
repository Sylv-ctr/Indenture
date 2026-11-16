# indenture — design contract

This document is normative. It defines the **formats and semantics**, not an
implementation. Any implementation that reads and writes these formats and honours these
semantics is conformant; `indenture.py` in this repository is one of them.

That separation is deliberate. The contract is the part worth keeping stable: a Python
library, a sidecar service and a hosted control plane should all agree on what a refusal
means and on how a journal is verified.

Version `0.1-draft`. Nothing here is stable until this line says otherwise.

---

## 1. Model

Three nouns.

**Actor** — anything that can act: an agent, a human, a scheduled job. Identified by a
stable string (`backend`, `qa`, `human`). An actor absent from the policy is **unknown**,
which is a distinct state from "declared and not permitted".

**Handoff** — one actor passing work to another. This is the unit that is authorized.

**State write** — an actor writing a value under a key. This is the unit that `replay` and
`blame` reconstruct.

A handoff is authorized *before* it happens. A state write is recorded *as* it happens. That
asymmetry drives §2.4.

---

## 2. Authorize

### 2.1 Evaluation

1. Rules are ordered. The **first matching rule decides** — `allow` or `deny`.
2. A rule matches on `from`, `to` and `kind`. Each takes a string, a list, or `"*"`. An
   absent `kind` means `"*"`.
3. A rule without an explicit `allow: true` denies. Permission is never implied by a rule's
   mere existence.
4. If no rule matches, `default` decides, and an absent `default` is `deny`.

### 2.2 Decisions are recorded

Every decision is journaled, **allow and deny alike**. A denial returned but not recorded
makes the system unauditable in exactly the case that matters.

A recorded decision carries the rule that decided (or `default`), both actors, both lanes,
the reason, and the digest of the payload.

### 2.3 Lanes

Each actor declares a blast radius in `actors`:

| Lane | Meaning |
|---|---|
| `contained` | effects confined to the run's own workspace |
| `wide` | effects visible outside the run, but reversible |
| `irreversible` | effects that cannot be undone |

The lane is recorded on every entry. Refusing the `irreversible` lane is the job of an
explicit rule — the shipped policy's first rule does exactly that, and it is first on
purpose, because §2.1 makes rule order the whole mechanism.

### 2.4 Unknown actors

- On a **state write**: recorded, flagged `unknown_actor`. The write already happened; a
  fact you refuse to record is a hole in the audit trail, which is worse than an
  unattributed fact.
- On a **handoff**: denied, with rule `unknown-actor`. It has not happened yet, and
  authorizing an actor you cannot name is the failure this tool exists to prevent.
- An **empty** actor list declares *nobody* known, not everybody. The opposite is a
  fail-open, and a fail-open default in a default-deny tool is invisible until it matters.

### 2.5 Exit codes

The hook contract depends on these, so they are public surface.

| Code | Meaning |
|---|---|
| `0` | allowed |
| `1` | the implementation failed — never a policy decision |
| `2` | denied by policy; the reason is on stdout, for the model to read |
| `3` | malformed input, or no such entry |
| `4` | journal unreadable, or failed verification |

A denial is `2`, never `1`. Python exits 1 on an unhandled exception and argparse exits 2 on
usage error; a caller must be able to fail closed on both a crash and a denial *and* still
tell them apart.

---

## 3. Journal

### 3.1 Entry

One JSON object per line, append-only. Field order on disk is not significant; the canonical
form in §3.2 is.

```jsonc
{
  "seq": 8,                        // position; a gap is a tampering signal
  "ts": "2026-11-16T09:38:44+00:00",
  "prev": "<sha256 of the previous entry>",
  "hash": "<sha256 of this entry without the hash field>",
  "event": "handoff",              // handoff | state | note
  "run": "",                       // optional correlation id

  // event = handoff
  "decision": "deny",              // allow | deny
  "from": "backend", "to": "deploy", "kind": "work",
  "from_lane": "contained", "to_lane": "irreversible",
  "rule": "rules[0]", "reason": "irreversible lane: …",

  // event = state
  "key": "contracts.md", "by": "data", "by_lane": "wide",
  "unknown_actor": true,           // present only when true

  // both
  "payload_digest": "531a7dc44be00ab9",
  "payload": { }                   // only when explicitly stored
}
```

### 3.2 Chaining

```
hash = SHA-256( canonical_json(entry without `hash`) )
```

`canonical_json` is UTF-8, keys sorted lexicographically, separators `,` and `:` with no
insignificant whitespace. The entry already contains `prev`, so the previous hash is inside
the hashed bytes rather than concatenated outside them. The first entry's `prev` is 64
zeros.

Two conformant implementations must produce byte-identical canonical forms. Avoid
floating-point values in payloads for that reason: float formatting does not survive the
requirement.

### 3.3 Digests, not payloads

By default an entry stores the **digest** of what was passed, not the payload.

Two reasons, both learned expensively by other audit systems: a journal that stores payloads
becomes a secrets leak, and it becomes a 2 GB file. Storing payloads is opt-in per call, and
an implementation MUST redact keys listed in the policy's `redact` before writing,
regardless of that opt-in.

The payload digest is truncated to 16 hex characters. It identifies a payload; it is not the
chain's integrity primitive, which is the full-length `hash`.

### 3.4 `verify`

`verify` MUST detect, and MUST name the position of:

- an **edited** entry — at that entry (`entry altered after writing`);
- a **deleted** entry — at the broken link, or as a sequence gap;
- **reordered** entries — at the first entry whose `prev` does not match;
- an **unparseable** line — reported, never skipped.

It MUST exit `4` on any of these. Tamper-*evident* means the detection is deterministic, not
probabilistic. It is not tamper-*proof*: whoever can rewrite the whole file can recompute
every hash. Ship the journal somewhere append-only if that matters, and the chain will tell
you whether what arrived matches what was written.

---

## 4. Replay

- `replay --until <seq>` — the state map as of that entry, inclusive.
- `blame <key>` — every write to that key, oldest first, with the last writer named.
- `why <seq>` — entries involving the same actors immediately before that one.

`why` does **not** infer causality. It shows neighbours and lets a human draw the line. A
tool that claims to explain *why* a multi-agent system did something, from a log alone, is
lying; the honest version shows the evidence and stops.

---

## 5. Hook contract

The hook is what turns a written rule into an applied one.

- It reads the proposed action on stdin as JSON.
- It exits with the codes in §2.5. On `2`, **stderr** carries the reason for the model
  (Claude Code's convention); the CLI's own `check` puts the reason on stdout.
- Tools not under policy are **not** journaled. A journal recording every unmonitored call
  is a journal nobody reads, and the signal disappears into it.
- A watched pattern is anchored at the start of the command, so `kubectl apply` matches and
  `echo kubectl apply` does not.

---

## 6. Non-goals

- Not a tracer. It answers the question tracing discards; run it alongside.
- Not an orchestrator. It does not schedule, retry or route.
- Not a sandbox. It records and decides; isolation is someone else's job.
- Not a causality engine. See §4.

---

## 7. Open questions

Recorded rather than resolved, so they are not quietly decided by the first implementation.

**Concurrent writers.** The current implementation reads the journal tail to compute `seq`
and `prev`, then appends. Two processes doing that at the same instant fork the chain.
`verify` catches it, so it fails loudly rather than silently — but concurrent agents are the
headline use case, so this is the most likely real-world failure. Candidates: an advisory
lock on the journal, a per-actor segment with a deterministic merge, or a single writer
process. Undecided.

**Append cost.** Computing the tip reads the whole journal, so appending is O(n) and a run
is O(n²). Fine for thousands of entries, not for millions. A sidecar index would fix it at
the cost of a second file that can disagree with the first.

**Checkpoints.** Whether `verify` should accept a published checkpoint hash, so an external
party can attest to a prefix of the chain without reading it.

**Approvals.** Whether an approval that opens the `irreversible` lane needs to be signed, or
whether being recorded in the chain is enough.
