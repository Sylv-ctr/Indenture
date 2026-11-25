# Indenture against the ANSSI agentic-AI guide

On 30 October 2026 ANSSI — the French national cybersecurity agency — published
*Sécuriser un système IA agentique*, V1.0, in its "Les Essentiels" collection
([page](https://messervices.cyber.gouv.fr/guides/essentiels-ia-agentique),
[PDF](https://messervices.cyber.gouv.fr/documents-guides/anssi_essentiels_ia_agentique_1.0.pdf)).
It sets out seven principles. Three of them describe, almost line for line, what this tool was
built to do — which is a coincidence: 0.1.2 shipped the day before we learned the guide existed.

This document maps the seven principles onto what Indenture actually does, **and onto what it
does not.** The second half is the useful one. If you are an engineer being handed that guide by
a security officer, this should let you work out in five minutes which boxes Indenture can help
with and which it cannot touch.

**What this document is not.** It is not a certification, an audit, an attestation, or any form
of compliance claim. ANSSI has not reviewed this tool, has not reviewed this document, and does
not endorse it. The verdicts below are a self-assessment by the tool's author, verified against
the code at version 0.1.3 and not against the README. Quotations from the guide are short, in
French, and attributed; read the PDF rather than trusting this summary.

**And one thing to settle before reading any of it.** Principle 5 asks for a filter "the agent
cannot bypass or modify". Indenture's enforcement runs as a host hook, so the enforcement is the
*host's*, not the tool's — and hosts can fail open. If the hook cannot start, Claude Code
reports the failure and runs the command anyway; an analogous failure is reported on Codex.
Nothing below is worth anything if `indenture doctor` does not say `healthy`.

---

## Summary

No principle is covered end to end. Two are outside what a tool of this kind can address at all.

| Principle | Indenture |
|---|---|
| 1 · Analyse and treat risks end to end | **Out of scope** — organisational |
| 2 · Limit the agentic system's autonomy | **Contributes one requirement** |
| 3 · Classify and control agent actions | **Partial — one of three action classes is missing entirely** |
| 4 · Separate and compartmentalise environments | **Out of scope**, one requirement contributed |
| 5 · Base authorisation on deterministic control | **Largely covered — two gaps, one of them structural** |
| 6 · Limit an agentic system's impact | **Partial** |
| 7 · Demonstrate and maintain control | **One requirement covered, now including the fourth link; the rest not** |

---

## 1 · Analyser et traiter les risques de bout en bout

**The guide asks** for a risk analysis from the design stage, security measures matched to each
identified risk, and: *« Bloquer la mise en service tant qu'un risque reste inacceptable. »*

**Indenture: out of scope.** This is a process a team runs, not a function a file provides. The
only honest connection is downstream: once you have decided which effects are unacceptable, the
policy file is one place to write them down in a form that executes.

---

## 2 · Limiter l'autonomie du système agentique

**The guide asks** you to define and document the agentic system's mission at design time and at
least annually, to widen autonomy only after verifying that security measures work, and —
the requirement that touches this tool — *« Faire respecter cet inventaire par des contrôles de
configuration externes au modèle. »*

**What Indenture does.** `policy.json` is exactly such a control: it is external to the model,
it declares each actor, the lane it operates in, and what it may hand off to whom. The model
does not read it, cannot widen it, and since 0.1.2 cannot write to it.

**What it does not do.** Defining the mission, documenting it, reviewing it annually, and
deciding when to widen autonomy are yours. Indenture has no notion of a "mission" to compare
anything against.

---

## 3 · Classer et contrôler les actions des agents

**The guide asks** you to define criticality criteria and document business impact, to sort
actions into *« exécution autonome, approbation humaine obligatoire et action interdite »*, to
submit critical actions to human approval, to *« Garder le mécanisme d'approbation hors de portée
du système agentique »*, to present the approver with the exact action, its purpose and its
expected effects, and to execute only the approved action.

**What Indenture does.** Two of the three classes exist. `allow` is autonomous execution;
a rule without `"allow": true` is a forbidden action, and `default: "deny"` makes "forbidden"
the fallback rather than an exception. Lanes (`contained` / `wide` / `irreversible`) are the
criticality axis. And the mechanism is out of the agent's reach: since 0.1.2 the hook refuses
writes to the policy, the hook itself, `indenture.py` and `.claude/settings*.json` as kind
`tamper`, from editing tools and from the shell alike.

**What it does not do — and this is the most interesting gap in the whole mapping.** There is no
**human-approval** class. Indenture answers yes or no; it cannot suspend an action and wait for
somebody. A denial routes the work to a human by telling the agent to ask the operator, and the
`reason` field is rendered back to the model so it can say what it wanted and why — but that is
a refusal with a hint, not an approval workflow. Nothing presents the exact action to an
approver, and nothing guarantees that only the approved action then runs.

This is the tool's largest missing piece against the guide, and it is the same gap as KYA
control 5 (recourse). It is an open design question, not a secret:
**[contributions and use cases welcome](../CONTRIBUTING.md).**

---

## 4 · Séparer et cloisonner les environnements

**The guide asks** for dedicated identities, secrets and connectors per environment
(development, evaluation, production), memory spaces separated per client organisation and per
environment, external communications routed only through controlled interfaces, and to
*« Considérer que toute donnée transmise à un modèle hébergé peut être accessible à son
fournisseur. »*

**Indenture: out of scope.** It does not manage identities, secrets, connectors, memory or
network egress. One requirement is contributed sideways: the journal lives in a directory, so a
separate environment gets a separate journal and policy by construction — which is weak
separation, not compartmentalisation.

The last point of this principle is worth reading twice if you journal payloads: see principle 6.

---

## 5 · Fonder l'autorisation sur un contrôle déterministe

This is the principle the tool was built for. It has four requirements; two are covered, one is
partial, one is not addressed at all.

**5.1 — A deterministic filter upstream of each tool or resource, independent of the agent, that
the agent cannot bypass or modify.** Covered in design, with the caveat at the top of this
document — and that caveat is now narrower than it was: Claude Code documents
`"onFailure": "block"` on a hook, which makes a hook that fails or times out **block** the call
instead of letting it through. It needs v2.1.295 or later, and the shipped settings example sets
it. Fail-open remains a property of the host, but the host offers a switch. The evaluator is deterministic: ordered rules, first match decides, no model in the
loop. It is a separate process reading a file the agent cannot write. It is **not**
unbypassable: an agent that writes a script and then runs it is seen as the command that runs
the script, and the host may fail open. Both limits are written in
[`SECURITY.md`](../SECURITY.md).

**5.2 — Authenticate the requester, automatically verify their rights, the action, its actual
parameters, its target, and compliance with business rules; use a policy the model cannot alter;
deny by default.** Partial, and the gap is named.

- *Authenticate the requester* — **not done.** An actor is a string, taken from
  `INDENTURE_ACTOR` or `argv[1]`. Anything that can set an environment variable can call itself
  anything. This is why the entry format reserves a `principal` field, written by nothing today:
  an entry without it means the actor was **not attributed**. See
  [`DESIGN.md`](DESIGN.md) §3.4.
- *Verify rights, action, target* — done, at the granularity of actor → target → kind.
- *Actual parameters* — partial. The bundled hook classifies by pattern-matching a command
  string, so it sees `vercel --prod` but does not parse arguments into fields. In library mode
  you call `authorize()` yourself and can be as precise as you like.
- *A policy the model cannot alter* — done since 0.1.2.
- *Deny by default* — done, and it is not configurable away by accident: an empty actor list
  declares *nobody*, not everybody.

**5.3 — Verify that a chain of individually authorised actions does not produce an effect that
business or security rules forbid.** **Not addressed.** Every call is evaluated on its own.
There is no window, no counter, no notion of a sequence. Three permitted handoffs that together
exfiltrate something are three allowed entries in the journal. The journal makes the sequence
*visible afterwards* — `log`, `why`, `replay` — but nothing refuses it at the time.

**5.4 — Grant agents no implicit trust or privileges.** Covered, and this was a real bug fixed
before publication: an empty actor list used to mean "everyone is known", which is fail-open at
the heart of a default-deny tool.

---

## 6 · Limiter l'impact d'un système agentique

**The guide asks** you to treat the system's inputs and outputs as untrusted, to limit the number
of successive calls between agents and alert on abnormal rates, to
*« Maintenir les secrets hors du contexte du modèle, des mémoires et des journaux »*, to provide
an emergency stop with access revocation triggerable by a supervision mechanism, to test
restoration, and to check that after a restoration an action already executed with an external
effect is not replayed.

**What Indenture does.** Secrets out of the journal is handled deliberately: payloads are stored
as digests by default rather than content, and the policy's `redact` list replaces named keys
before anything is written. The default list covers `api_key`, `token`, `password`,
`authorization` and `secret`; it is yours to extend, and it is worth extending before you turn
on payload storage.

`replay` reconstructs state as of an entry. It is **read-only** — it recomputes a view from the
journal and never re-executes anything — so the last requirement of this principle is satisfied
by construction rather than by a feature.

**What it does not do.** No rate limiting between agents, no anomaly alerting on call frequency,
no emergency stop. Revoking access means editing the policy, which affects the next call; a run
already in flight continues. In-run revocation needs something the local file cannot provide.

---

## 7 · Démontrer et maintenir la maîtrise du système

Five requirements. One is what this tool is for; the other four are not its job.

**7.1 — Inventory of software components, system prompts and dependencies; version what you
build; check provenance, integrity and known vulnerabilities.** Out of scope.

**7.2 — Test before deployment and regularly after, to detect model drift; have a rollback.**
Out of scope for the agentic system. (Indenture has 89 tests of its own, one per claim its
documentation makes. That is hygiene, not compliance.)

**7.3 — Supervise production actions against the documented mission and authorised tools, to
detect goal changes and unusual action sequences (UEBA).** Partial, and the division is clean:
Indenture produces the **raw material** — every authorised and refused handoff, with actor,
target, kind, lane, the rule that decided, and a digest of what was passed — and performs **no
supervision whatsoever**. No mission to compare against, no baseline, no anomaly detection.
Pointing a detection tool at `journal.jsonl` is a reasonable thing to do; Indenture will not do
it for you.

**7.4 — Keep system logs out of the agent's reach to preserve their integrity, so that after an
incident you can reconstruct the full sequence of request, authorisation, action and result.**
This is the requirement Indenture covers best, and it still does not cover it entirely.

Out of the agent's reach: since 0.1.2, yes, for the obvious paths. Integrity: each entry's hash
covers its own fields and the previous hash, and `verify` recomputes the chain. Reconstruction:
`log`, `why`, `replay` and `blame` rebuild the sequence.

**The guide asks for four links. As of 0.1.3 the journal records four** — this gap was found by
writing this document and closed two days later. A `PreToolUse` hook is asked before the fact
and cannot know the outcome, so the fourth link comes from a second hook: `PostToolUse` appends
a separate `result` entry joined to the decision by the host's `tool_use_id`. Separate, because
the journal is append-only and an entry whose bytes change is an entry whose hash lied.

**Three limits, and they matter more than the feature.** `tool_use_id` needs Claude Code
v2.1.257 or later; without it there is nothing to join on, and the implementation records the
result as `uncorrelated` rather than guessing, because an outcome attached to the wrong decision
is worse than one attached to none. `PostToolUse` fires after a tool *succeeds*, so a failure may
produce no entry at all. And an unwatched call was never journaled going in, so there is nothing
to close coming out.

Therefore, and this is written into the contract rather than left to be discovered: **an entry
with no result means the outcome was not recorded. It never means the action failed, and never
that it succeeded.** Same rule as `principal` and `receipt`, for the same reason — in an audit
tool, a silence nobody defined is a defect. See [`DESIGN.md` §3.5](DESIGN.md).

Two integrity limits are also written rather than glossed: **truncating the tail of the journal
leaves a valid chain** — a shorter chain still verifies, so only a third-party receipt will
catch it — and a chain is *tamper-evident*, not *tamper-proof*: whoever can rewrite the file can
recompute every hash. There is a stronger version of this objection worth knowing before you
rely on any hash-chained log, including this one: a signed chain establishes **integrity but not
completeness**, so an omitted action verifies perfectly well
([arXiv 2610.07459](https://arxiv.org/pdf/2610.07459)). That is not answered by better
cryptography; it is answered by an independent recorder.

**7.5 — Keep the register of policy owners, alerts and exceptions up to date.** Out of scope.
Though `blame` and `git log` on a versioned `policy.json` tell you who changed a rule and when,
which is a start.

---

## The honest ledger

Four things the guide asks for and this tool does not do. None of them is hidden anywhere else
in the documentation, and each is an open design question rather than a roadmap promise.

1. **No human-approval path** (principle 3). Yes or no, never "wait".
2. **No requester authentication** (principle 5.2). An actor is a string; `principal` is
   reserved and unwritten.
3. **No chain-of-actions check** (principle 5.3). Each call is judged alone.
4. **No in-run revocation** (principle 6). Editing the policy catches the next call, not the
   current run.

*Closed on 25 November: the result of an action was not recorded (principle 7.4). It is now, in
0.1.3, with its three limits written down — see principle 7 above. The gap was found by writing
this document, which is the only argument this page needs for existing.*

And three limits that are properties of the approach rather than missing features: enforcement
belongs to the host and hosts can fail open; a script written and then executed is not seen for
what it is; a truncated journal still verifies.

## How to use this document

As something to put on the table, not as an answer. If your security officer hands you the
seven principles, this tells you that one tool covers most of principle 5, part of 3, 6 and 7,
and nothing of 1 and 4 — which is a sane result for a single file of standard-library Python,
and a terrible result if anyone expected it to be a compliance product.

If you work in a context where one of the five gaps above is the one that matters, that is worth
more to this project than a star. [Open an issue](https://github.com/Sylv-ctr/indenture/issues)
and say which, and what breaks for you.

---

*Written on 24 November 2026 against Indenture 0.1.3 and ANSSI V1.0 (10/26). The guide may be
revised; this document is not updated automatically. Read the PDF.*
