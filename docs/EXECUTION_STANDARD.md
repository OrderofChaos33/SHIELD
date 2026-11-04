# SHIELD Execution Standard — Invariant-First Security & Automated Fuzzing

Version 1.0 · Adopted 2026-11-04 · Status: STANDING — applies to every
commit to this repository, and is the reference standard for the
founder's other codebases (SINCOR2: Solidity/Foundry track).

Philosophy: institutional audit rigor is a *process*, not a purchase.
This standard buys with discipline what audits buy with money:
invariants stated before code, randomized stateful stress before
merge, static gates that cannot be waved through, and a core small
enough to actually reason about. It extends — and does not replace —
the standing TDD builder contract (green baseline, fix code never
tests, halt rather than weaken a test, no commit without numbers).

## 1. Invariant-First Architecture

**Rule: no state-changing core function is written before its
invariants are written down.**

- Every module carries its invariants in `docs/INVARIANTS.md`, each
  with a stable ID (`INV-L2-03`) and the test that enforces it.
- An invariant is a statement that must hold after *every* operation,
  not for one example input: bounds, conservation, authorization,
  ordering, idempotence.
- Solidity track: every vault/accounting module ships Foundry
  `invariant_*` stateful tests covering solvency (assets ≥ shares
  obligations), no unauthorized share inflation, and privileged-role
  lockdown, written *before or with* the module — never after.
- Rust track: invariants are enforced by property tests (`proptest`)
  over randomized inputs and randomized operation sequences.
- Changing an invariant requires changing `INVARIANTS.md` in the same
  commit, with the reason in the commit message. Silently weakening an
  invariant is the single worst offense under this standard.

## 2. Stateful Fuzzing Protocol

**Rule: unit tests with static inputs are the floor, never the ceiling.**

- Randomized actors drive random call sequences against the state
  machine (deposits/withdrawals/hooks on the Solidity side; frames /
  slices / attestations / grants on the Rust side), asserting every
  invariant after every step.
- Pre-merge campaigns (local, before any push):
  - Solidity: `forge test --fuzz-runs 50000` (invariant suites included)
  - Rust: `PROPTEST_CASES=4096 cargo test -p shield-core --test properties`
  - Rust deep campaigns (nightly / pre-release, not per-commit):
    `cargo fuzz` targets on parsers and frame handling, time-boxed 10 min each.
- A fuzz failure is never "flaky." The seed is recorded, the case is
  shrunk, the minimized reproducer becomes a permanent regression test.

## 3. Static Gatekeeping (Local + CI, Zero Exceptions)

**Rule: flawed code is intercepted by machines before humans review it.**

Local, via `scripts/pre-commit-shield` (install: `sh scripts/setup-hooks.sh`):
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- Full test suite (unit + integration + properties at CI case counts)
- Secret scan of the staged diff (keys, tokens, telemetry markers)

Solidity repos: `slither . --json slither-report.json` in the same hook.

CI (`.github/workflows/ci.yml`) re-runs all of it. **Merge/deploy gate:**
- **Zero** High or Medium static-analysis findings (Slither / clippy lints
  classified as correctness or security).
- **100%** invariant + property test pass rate. Not 99%. There is no
  "known failing" state on main; a failing invariant reverts the merge.
- Full-loop integration test present for any cross-module change
  ("wired, not just green" — inherited from the SINCOR standard).

## 4. Isolation of Core State & Attack-Surface Minimization

**Rule: the core that holds value or secrets stays lean, decoupled,
and suspicious of everything outside it.**

- Accounting / key / audit logic lives in small, single-purpose files;
  peripheral features (UI, hooks, integrations) never import core
  internals except through the audited public surface.
- Every external integration is treated as hostile: BLE peripherals,
  oracles, Uniswap v4 pools/hooks, agent registries. All return data is
  validated; all value-moving calls carry explicit bounds (slippage,
  caps, deadlines) and revert rather than proceed on inconsistency.
- New dependencies are attack surface: each one needs its ADR-001 line
  (what, why, removal cost) in the same commit that adds it.

## 5. Enforcement & Exceptions

- The gates are scripts, not intentions: if it isn't in
  `pre-commit-shield` or CI, it isn't a gate.
- Exceptions require a written note in the commit + `INVARIANTS.md`
  entry marked `EXCEPTION` with an expiry date. Expired exceptions
  block merges until resolved.
- This document changes only by explicit founder decision. Version it.

*Provenance: generalized from the SINCOR2 builder gates that already
caught real losses-in-waiting — the TDD contract, the pool
conservation invariant suite (the UNCX bug-class hedge), mutation
testing on money-path code, and the "wired, not just green" rule
learned when a 49/49-green activity engine shipped with its pool
handoffs unconnected.*
