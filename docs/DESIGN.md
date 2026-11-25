# indenture — design contract

This document is normative. It defines the **formats and semantics**, not an
implementation. Any implementation that reads and writes these formats and honours these
semantics is conformant; `indenture.py` in this repository is one of them.

That separation is deliberate. The contract is the part worth keeping stable: a Python
library, a sidecar service and a hosted control plane should all agree on what a refusal
means and on how a journal is verified.

## Stability — read this before implementing

Version `0.1-draft`. **Nothing here is stable, and it will not be frozen before two standards
land.** If you are about to write a second implementation, that is the one thing you need from
this page.

Two documents are going to decide whether this format is reusable or has to be redone:

- **ISO/IEC 24970, *AI system logging*** — status "Under publication" as of 23 November 2026,
  with final production steps given as up to seven weeks, so it is **not purchasable yet**.
  The CEN is taking it up as `FprEN ISO/IEC 24970`.
- **prEN 18229-1** — logging, transparency and human oversight; covers Articles 12 to 14 of the
  EU AI Act.

The European Commission's standardisation request to CEN-CENELEC covers "record keeping through
logging capabilities of AI systems" explicitly. Neither text has been read by the author of this
one: they are paid standards and the first is not out. **Any alignment claim here would be
invented.** When they are available, this contract gets checked against them, and the entry
schema in §3 may change — field names, required fields, or how a decision is expressed.

What that means in practice:

- **Freezing now would be the expensive mistake.** A format published as stable in November and
  contradicted by an ISO standard in January is a format nobody trusts twice.
- **Build on it anyway if it solves your problem today** — but pin the version you built
  against, and expect a migration note rather than a silent change. Journals already written stay
  verifiable: each entry's hash covers its own fields, so adding a field never invalidates an
  older entry (see §3.4).
- **The two reserved fields are the stable part of the instability.** `principal` and `receipt`
  exist precisely so that attribution and anchoring can arrive without a format break, and their
  absence already has a defined meaning.

This section is the honest version of a promise this project cannot make yet. It will be replaced
by a stability guarantee, with a date, once there is something to align to.

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
  "payload": { },                  // only when explicitly stored

  // reserved — see §3.4. Never written by this version.
  "principal": { },
  "receipt": { }
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

### 3.4 Reserved fields: `principal` and `receipt`

Two field names are reserved now and written by no implementation yet. They are declared here
so that their **absence is interpretable forever**, which matters more than it sounds.

**`principal` — on whose behalf.** An entry today says *actor `backend` did this*. But an actor
is a string someone typed into a local file: nothing states who it was acting for, and nothing
stops whoever can edit the file from choosing the name. `principal` will carry the identity the
actor was exercising delegated authority for, and whether that identity was **verified** (a
token issued by an external authority) or merely **declared** (a string). The vocabulary is
that of a mandate: the principal grants the authority, the agent exercises it. An agent is an
instrument, never a person.

**`receipt` — proof a third party saw the entry.** The chain detects an edited, deleted or
reordered entry. It does not detect the whole file being rewritten from scratch with every hash
recomputed, which is why §3.5 says tamper-*evident* and not tamper-*proof*. A `receipt` is what
an external service returns on receiving an entry — an acknowledgement held by somebody who is
not the author. You can rewrite your own ledger; you cannot rewrite the other party's
acknowledgement of it.

**The rule that makes reserving them worthwhile:**

> An entry without `principal` means the actor was **not attributed**. An entry without
> `receipt` means the entry was **not anchored**. This holds for every entry ever written,
> including every entry written before these fields existed.

Without that sentence written down before the fields are used, a later reader cannot tell
"the tool could not record this" from "there was nothing to record" — and in an audit tool,
an uninterpretable silence is a defect.

**On forward compatibility.** Adding a field later does *not* break existing journals: each
entry's hash is computed over its own fields, so an old entry still verifies against itself.
What a late addition breaks is the *meaning* of an absent field, which is what this section
fixes. Recorded here because the opposite was asserted during design and turned out to be
wrong.

### 3.5 `verify`

`verify` MUST detect, and MUST name the position of:

- an **edited** entry — at that entry (`entry altered after writing`);
- a **deleted** entry — at the broken link, or as a sequence gap;
- **reordered** entries — at the first entry whose `prev` does not match;
- an **unparseable** line — reported, never skipped.

It does **not** detect entries removed from the **end**: a truncated journal is a shorter chain,
and a shorter chain is valid. Detecting it needs the tip held by someone other than the author,
which is what `receipt` (§3.4) is reserved for.

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

**Concurrent writers — resolved for the single-machine case.** An exclusive lock on
`journal.lock` makes read-tip-then-append indivisible (`fcntl`, or `msvcrt` on Windows).
Measured before the fix: twenty-four concurrent writers produced eight distinct `seq` values.
After: twenty-four distinct values and an intact chain.

An implementation MUST serialise that window. Where no locking primitive exists it MUST warn
and still record, because a journal that declines to write is a hole in the audit trail.

Still open: a journal on a network filesystem, where the lock may be accepted and silently not
enforced; and writers on **different machines**, which no local lock can serialise. The latter
is not a bug to fix locally — it is the case a central receiver answers (see
`claude/ADR-004`), and a per-actor segment with a deterministic merge remains the alternative
if that receiver never exists.

**Append cost.** Computing the tip reads the whole journal, so appending is O(n) and a run
is O(n²). Fine for thousands of entries, not for millions. A sidecar index would fix it at
the cost of a second file that can disagree with the first.

**Checkpoints.** Whether `verify` should accept a published checkpoint hash, so an external
party can attest to a prefix of the chain without reading it.

**Approvals.** Whether an approval that opens the `irreversible` lane needs to be signed, or
whether being recorded in the chain is enough.
