# Requirements Specification: FPP Attestation Ledger — v1 initialization

**Generated:** 2026-08-27T17:40:00Z
**Status:** Complete
**Questions Answered:** 10 / 10
**Source plan:** `fpp-attestation-ledger-plan.md` (this folder; tailored 2026-08-27, authoritative for schema/rule detail)

## Overview

Initialize and implement v1 of the public FPP attestation ledger — a Git-based SSOT of
declaration-only adoption filings for the Freedom-Preserving Protocol, stewarded by FIDES-ANIMA
via OpenPGP admission signatures. The plan document is complete and verified against the
upstream FPP tree; this spec fixes the ten operator decisions and records the verification
findings the implementation must honor. Every entry is `declaration-only`; the ledger never
claims behavioral compliance or `peer-advertisable` assurance.

All 10 answers were **Yes** (defaults accepted throughout).

## Functional Requirements

- **FR1 (D-Q1):** Implementation root is `I:\Dev\Projects\FIDES-ANIMA\fpp-attestation-ledger`,
  initialized as the git repo pushed to `github.com/FIDES-ANIMA/fpp-attestation-ledger`.
  `.resources/` (operator-held cert source) is git-ignored; the published cert copy is
  `stewards/fides-anima.asc`.
- **FR2 (D-Q2):** The GitHub repo is created **public** from day one.
- **FR3 (D-Q3):** Initial launch seeds both §7 entries — `attestations/axiom.yaml`
  (`accepted`, identity-bound) and `attestations/hermes-default.yaml` (`reviewed`,
  operator-filed). Axiom's `fpp_id` must be confirmed against the live identity key before merge.
- **FR4 (D-Q4):** Offline steward-key access is available; Phase 3 admissions (detached `.asc`
  per file, `admissions/*.json` receipts, OpenPGP-signed merges) are in scope for initial launch.
- **FR5 (D-Q5):** CI enforces the **strict** lifecycle stance: a first filing of `accepted` is
  rejected unless `attestation.notes` records prior inspection. The GOVERNANCE.md relaxation is
  documented but disabled.
- **FR6:** Full scope is plan §8 Phases 1–4 (scaffold, schema+validation, seeds, documentation
  polish). Phase 5 items remain out of scope for v1.

## Technical Requirements

- **Affected areas:** entire new repo tree per plan §2 — `README.md`, `GOVERNANCE.md`,
  `SCHEMA.md`, `LICENSE` (HUL v1.0), `stewards/`, `schema/attestation.schema.json`,
  `attestations/`, `revocations/`, `admissions/`, `scripts/validate.py`,
  `scripts/verify-signatures.py`, `.github/workflows/validate.yml`, plus `requirements.txt`
  and a pytest suite (new relative to the plan).
- **TR1 (E-Q1):** SCHEMA.md and the validator document that `adoption.constitution_hash` is the
  SHA-256 of **`constitution.json`** (`71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993`).
  Verified 2026-08-27: `constitution.yaml` hashes to `da58a4f3…58` and must not be cited as the
  hash source.
- **TR2 (E-Q2):** Steward admissions are signed **only** with the long-lived signing subkey
  (expires 2028-08-26) of cert `715E182192C546A612F8E6D64A9E2AFF11CB1432`; never the subkey
  expiring 2026-08-29. `verify-signatures.py` accepts any signing subkey resolving to the pinned
  primary fingerprint (from `stewards/expected-key-ref.txt`), and must handle gpg behavior around
  expired subkeys explicitly.
- **TR3 (E-Q3):** `verify-signatures.py` shells out to system `gpg` using an ephemeral temporary
  `GNUPGHOME` (import pinned cert → verify → discard). No pure-Python OpenPGP dependency.
- **TR4 (E-Q4):** Committed pinned `requirements.txt`: `pyyaml`, `jsonschema`, `cryptography`
  (Ed25519 verification and pubkey→fingerprint cross-check for validation rules 14 and 31).
  CI pins Python 3.11. No dependency on unpublished `@ovrsr/fpp-*-core` npm packages — FPP enums
  and the identity regex are frozen into `attestation.schema.json`.
- **TR5 (E-Q5):** The plan §8 Phase 2 checklist (15 must-pass/must-fail cases) is a committed
  pytest suite executed by the CI workflow, developed red-green per the workspace TDD rule.
- **Data flow:** contributor PR (YAML per §3 schema) → CI (rules 1–31, §5; PRs reject `*.asc` /
  `admissions/**`) → offline steward admission (detached `.asc` + receipt + signed merge) →
  consumers clone, `gpg --verify`, and run the validators.
- **Integration points:** upstream `ovrsr/freedom-preserving-protocol` (frozen vocabulary only,
  plus a Phase 4 README-link PR); GitHub branch protection (PR + CI required, merge restricted
  to steward identity, signed merge commits); org GPG key upload for verified-badge merges.

## Recommended Areas (for /plan)

- **Primary:** `schema/attestation.schema.json`, `scripts/validate.py` (rules 1–31), and the
  pytest suite — the bulk of the logic and risk.
- **Supporting:** `scripts/verify-signatures.py` + CI workflow (PR/main mode split); repo
  scaffold and governance docs; seed entries + steward admission procedure; GitHub settings
  (public repo, branch protection, topics, description).

## Acceptance Criteria

- [ ] Repo exists publicly at `FIDES-ANIMA/fpp-attestation-ledger` with the §2 tree, HUL v1.0
      license, and no `.resources/` or secret-armor content anywhere in history
- [ ] `python scripts/validate.py --schema schema/attestation.schema.json --all` exits 0 on the
      seeded tree and the pytest suite passes all 15 §8 Phase-2 cases (must-fail cases fail with
      messages naming the colliding path / suggested slug where required)
- [ ] CI runs on PRs and main with `fetch-depth: 0`; PR mode rejects added/modified `*.asc` and
      `admissions/**`; main mode requires a verifiable `.asc` and admission receipt per record
- [ ] `stewards/fides-anima.asc` fingerprint equals `stewards/expected-key-ref.txt`
      (`openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`); mismatch fails CI
- [ ] Both seed entries admitted on `main` with `.asc` signatures made by the long-lived subkey
      and verifiable via `gpg --verify` in a clean GNUPGHOME; merge commits GitHub-verified
- [ ] Axiom `fpp_id` confirmed against the live key (`deriveAgentIdV2`) before its seed merge
- [ ] Strict first-filing rule active: test case proves a fresh `accepted` filing without
      inspection notes fails CI
- [ ] README states the evidence ceiling (declaration-only; admission ≠ compliance), documents
      intake paths A/B/E/F and consume steps, and any adopter-count badge is labeled
      "declared adopters"

## Assumptions

- None from `idk` defaults — all 10 questions answered explicitly Yes.
- The steward operator can produce the long-lived-subkey signature offline (secret key never
  enters git, CI, or GitHub Actions secrets).
- Constitution pin stays `1.0.0` / `71bf60ad…` until upstream ships amendments (currently
  PROPOSED).

## Next Steps

1. Review this spec.
2. Run `/plan` with this spec and `fpp-attestation-ledger-plan.md` as the source documents
   (plan file per praxiscode workflow: `docs/plans/2026-08-27-fpp-attestation-ledger-v1.md`).
