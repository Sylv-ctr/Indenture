# Security

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository
([Security → Report a vulnerability](https://github.com/Sylv-ctr/Indenture/security/advisories/new)).
That gives us a private thread before anything is public.

Please do not open a public issue for a bypass. This is an authorization tool: a public
description of how to get past it is useful to the wrong person first.

One maintainer, working on this part-time. You will get an acknowledgement within a few days and
an honest estimate rather than a promise. If a fix needs to wait, the advisory will say why.

## In scope

Anything that makes the tool answer *allow* where the policy says *deny*, or that makes an
altered journal verify:

- a command that should match a rule and does not, or matches the wrong one
- a policy that parses into something other than what it reads like
- a journal that `verify` accepts after being edited, truncated or reordered
- a redaction that leaks the value it was supposed to replace
- a path where `authorize` returns a decision without journaling it

## Out of scope, and why

These are documented limitations, not vulnerabilities. They are in the README and in
`docs/DESIGN.md`, and a report that restates one of them will be closed with a pointer.

- **Rewriting the whole journal.** The chain is tamper-*evident*, not tamper-*proof*. Someone
  who can rewrite the file can recompute every hash. Ship the journal somewhere append-only if
  you need more.
- **The host failing open.** If the host runs a command when the hook cannot start, the gate is
  gone and this tool never ran. That is the host's behaviour, not a flaw here — see "Read this
  before you trust it" in the README, and run `indenture doctor`.
- **A process that ignores the exit code.** This is not a sandbox. It records; enforcement is
  whoever reads the answer.
- **Anyone who can edit `policy.json`.** The policy is a local file with local permissions. An
  actor who can rewrite it can authorize themselves. Anchoring an actor to an identity that a
  local file cannot forge is outside this tool.
- **An actor naming itself.** An actor is a string in a local file. Attribution to an identified
  principal is the `principal` field, reserved and not implemented — `docs/DESIGN.md` §3.4.

If you think one of these is worse than described, that is worth reporting. The claim being
documented does not make it correct.
