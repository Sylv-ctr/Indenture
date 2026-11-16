# Indenture — design contract

This document is normative. It defines the **formats and semantics**, not an
implementation. Any implementation that reads and writes these formats and honours these
semantics is conformant; the reference implementation in this repository is one of them.

That separation is deliberate. The contract is the thing worth being stable: a Python
library, a sidecar service and a hosted control plane should all agree on what a refusal
means and on how a ledger is verified.

Version: `0.1-draft`. Nothing here is stable until this line says otherwise.

---

## 1. Model

Three nouns.

**Actor** — anything that can act: an agent, a human, a scheduled job. An actor is
identified by a stable string (`backend`, `qa`, `sylvain`). An actor that is not declared is
**unknown**, which is a distinct state from "declared and not permitted".

**Handoff** — one actor passing work to another. This is the unit the policy authorizes.

**State write** — an actor writing a value under a key. This is the unit `blame` and
`replay` reconstruct.

A handoff is authorized *before* it happens. A state write is recorded *as* it happens.
That asymmetry drives the rule in §2.4.

---

## 2. Authorize

### 2.1 Evaluation

1. Rules are ordered. The **first matching rule decides** — `allow` or `deny`.
2. If no rule matches, the **default** decides.
3. The default is `deny`. An implementation MUST NOT provide a way to make the default
   `allow`; a policy that wants permissiveness writes an explicit terminal rule, so that
   permissiveness is visible in the policy file rather than hidden in a flag.

### 2.2 Decisions are recorded

Every decision is written to the ledger, **allow and deny alike**. A denial that is returned
but not recorded makes the system unauditable in exactly the case that matters.

A recorded decision carries: the rule that decided (or `default`), the actors, the lane, and
the digest of the payload.

### 2.3 Lanes

Every handoff declares a blast radius:

| Lane | Meaning |
|---|---|
| `contained` | effects are confined to the run's own workspace |
| `wide` | effects are visible outside the run but reversible |
| `irreversible` | effects cannot be undone |

**The `irreversible` lane never opens automatically.** It requires a recorded approval from
a human actor. An implementation MUST NOT provide a configuration that grants it by rule
alone.

### 2.4 Unknown actors

- On a **state write**: recorded and flagged. The write already happened; a fact you refuse
  to record is a hole in the audit trail, which is worse than an unattributed fact.
- On a **handoff**: denied. The handoff has not happened yet, and authorizing an actor you
  cannot name is the failure this tool exists to prevent.

### 2.5 Exit codes

The hook contract depends on these being stable.

| Code | Meaning |
|---|---|
| `0` | allowed |
| `2` | denied by policy (reason on stdout, for the model to read) |
| `3` | malformed input |
| `4` | ledger unreadable or failed verification |

A denial is `2`, never `1`: `1` is reserved for the implementation failing, which must never
be mistaken for a policy decision.

---

## 3. Record

### 3.1 Entry

One JSON object per line, append-only. Field order is not significant; the canonical form
in §3.2 is.

```json
{
  "seq": 41,
  "ts": "2026-11-16T09:12:04.221Z",
  "kind": "handoff | write | decision | approval",
  "actor": "backend",
  "peer": "qa",
  "lane": "contained",
  "key": "build.artifact",
  "digest": "sha256:9f2b…",
  "decision": "allow | deny",
  "rule": "r-07 | default",
  "reason": "…",
  "prev": "sha256:4c81…",
  "hash": "sha256:7ae0…"
}
```

### 3.2 Chaining

```
hash = SHA-256( prev_hash || canonical_json(entry without `hash`) )
```

`canonical_json` is UTF-8, keys sorted lexicographically, no insignificant whitespace, no
floating-point values. The first entry's `prev` is 64 zeros.

Floats are excluded because two conformant implementations must produce byte-identical
canonical forms, and float formatting does not survive that requirement.

### 3.3 Digests, not payloads

By default the ledger stores the **digest** of what was handed over, not the payload.

Two reasons, both learned the hard way by other audit systems: a ledger that stores payloads
becomes a secrets leak, and it becomes a 2 GB file. Storing payloads is opt-in, per key, and
an implementation MUST redact keys matching the configured sensitive patterns before writing
regardless of that setting.

### 3.4 `verify`

`indenture verify` MUST detect, and MUST name the position of:

- an **edited** entry — at that entry;
- a **deleted** entry — at the broken link;
- **reordered** entries — at the first entry whose `prev` does not match.

It MUST exit `4` on any of these. "Tamper-evident" means the detection is deterministic,
not probabilistic.

---

## 4. Replay

- `replay --until <seq|ts>` — reconstruct the state map as of that point.
- `blame <key>` — the last actor to write that key, with the entry's `seq`.
- `why <seq>` — the entries immediately around that one, as context.

`why` does **not** infer causality. It shows neighbours and lets a human draw the line. A
tool that claims to explain *why* a multi-agent system did something, from a log, is lying;
the honest version shows the evidence and stops.

---

## 5. Hook contract

The hook is what turns a written rule into an applied one.

- It reads the proposed action on stdin as JSON.
- It exits with the codes in §2.5.
- On `2`, stdout carries the reason, which the caller is expected to return to the model.
- Tools that are not under policy are **not** recorded. A ledger polluted with every
  unmonitored call is a ledger nobody reads.

---

## 6. Non-goals

- Not a tracer. It does not replace execution tracing; it answers the question tracing
  discards.
- Not an orchestrator. It does not schedule, retry or route.
- Not a sandbox. It records and authorizes; isolation is someone else's job.
- Not a causality engine. See §4.

---

## 7. Open questions

Recorded here rather than resolved, so that they are not quietly decided by the first
implementation.

- Concurrent writers to one ledger file: a lock, a per-actor segment with a merge, or a
  single writer process. Undecided.
- Whether `verify` should support a published checkpoint hash, so that an external party can
  attest to a prefix of the chain without reading it.
- Whether approvals in the `irreversible` lane need to be signed, or whether being recorded
  in the chain is enough.
