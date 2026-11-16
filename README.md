# Indenture

**Chain of custody for multi-agent systems.**

Who was allowed to hand work to whom, what was handed over, and how to replay from the
point where it should not have been allowed.

> **Status: pre-release.** The design contract in [`docs/DESIGN.md`](docs/DESIGN.md) is
> settled; the implementation is being written in the open. Nothing here is stable yet.

---

## The problem

Tracing shows you the execution path. It does not tell you whether a handoff should have
been permitted in the first place.

Three failure modes keep being described by people running more than a couple of agents:

- An upstream agent passes malformed state, a downstream agent does something destructive,
  and the root cause is three steps back.
- Concurrent agents overwrite shared state and produce **zero errors, plausible output,
  wrong result** — a concurrency bug that looks like model quality regression, and that
  gets worse as you add agents.
- A rule written in a prompt is a suggestion. The model can ignore it, and nothing records
  that it did.

Observability tools answer *what happened*. None of them answer *what was this system
refused permission to do, and why* — because refusals are the half that tracing throws
away.

## Three verbs

**Authorize.** A default-deny policy over who may pass what to whom. First matching rule
decides; with no matching rule, the default decides, and the default is `deny`. Refusals are
recorded, not just returned.

**Record.** Append-only, hash-chained, tamper-evident. Each entry carries the hash of the
previous one. An entry that is edited, deleted or reordered is *detected* by `indenture
verify` — not merely improbable.

**Replay.** Reconstruct state at any point (`replay --until`), find who last wrote a key
(`blame`), read the local context around an entry (`why`).

## Why the name

A medieval indenture was a contract written twice on one sheet, then cut along a jagged
line. Each party kept a half. Fitting the two halves back together proved the document was
genuine and untampered. It is a hash chain, five centuries early.

## Runtime enforcement

The strategic difference between this and a logging library is the hook: the policy is
applied by the runtime, not written in a prompt the model may ignore. A denied tool call
exits non-zero and the reason is returned to the model.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the policy format, the ledger entry format, the
verification semantics and the hook contract.

---

## If you run more than three agents, I want to hear from you

This is the part I cannot find out by reading. There is no reliable public data on how many
teams run more than three or five code agents in production — and that number is the whole
question.

So if you do: **open an issue** and say how many agents, what they hand to each other, and
what broke last. Especially what broke last. I will take a wrong answer about my own design
over a polite one.

## License

MIT.
