# Contributing

## What is most useful right now

**A report from real use.** How many agents, what they hand to each other, and what broke last.
Especially what broke last. Every defect worth fixing in this repository so far came from
installing it somewhere real, not from thinking about it — including the one where the watched
command list turned out to watch nothing at all on the first repository it met.

**A hook adapter for another host.** The core knows nothing about any provider, but the only
enforcement example here speaks Claude Code's shape. Codex, Cursor and Grok Build converged on
the same `exit 2 blocks` convention with different config paths and field names, so an adapter
is small. This is the contribution I would most like to receive.

**A wrong answer about the design.** More useful than a polite one.

## Before writing code

Open an issue first for anything beyond a fix. Several tickets here are labelled `design` and
are deliberately not being built: they are waiting for someone's real use to say what the shape
should be, and a patch that guesses the shape costs more to review than it saves.

## If you do send a patch

- One test per claim. The suite is written so that each test corresponds to something the README
  or `docs/DESIGN.md` asserts; a change to behaviour changes both.
- `pip install -e ".[dev]" && pytest` — standard library only, no runtime dependencies. A patch
  that adds a dependency needs to argue for it.
- The journal format and the exit codes are the stable surface. Changing either is a breaking
  change and needs a reason in `docs/DESIGN.md`, not only in the commit message.
- Default-deny is not negotiable. A patch that makes an unmatched case pass is a bug, however
  convenient.

## Licence of contributions

Unless you state otherwise, any contribution you intentionally submit for inclusion in this
project is licensed under **both** the MIT licence and the Apache License 2.0, at the recipient's
option — the same terms the project is distributed under (see
[`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE)).

There is no separate agreement to sign. This paragraph exists because the project is dual
licensed: without it, a patch would arrive under no stated terms and nobody downstream could tell
which licence covered it.
