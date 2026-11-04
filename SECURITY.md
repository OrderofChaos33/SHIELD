# Security Policy

SHIELD is personal defensive infrastructure. Security issues are the
product's reason to exist, so they are treated accordingly.

## Reporting

This is a private, single-user project. If you have access to this
repository and find a vulnerability — especially anything that could
let raw telemetry, an unscrambled topography, a session key, or an
unlogged release escape the core — stop, do not open a public issue,
and contact the repository owner directly through the channel you
already have.

## Rules for contributors (including future me)

1. No real telemetry in the repo. Synthetic only. No exceptions.
2. No secrets, device IDs, MAC addresses, or passphrases in the tree.
3. `ble`, `crypto`, `storage`, `audit` changes need an adversarial
   test: write the attack first, watch it fail, then merge.
4. New dependencies require a note in `docs/ADR-001-deps.md`:
   what it does, why it's needed, what it replaces if removed.
5. If a change weakens a default (raises ε, widens a sequence window,
   adds a permissive mode), that change is a security decision and
   must say so in the commit message, in those words.
