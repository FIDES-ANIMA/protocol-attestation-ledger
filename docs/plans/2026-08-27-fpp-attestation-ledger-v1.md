# FPP Attestation Ledger v1

**Status:** PENDING — task-level Definitions of Done  
**Created:** 2026-08-27  
**Sequencing overlay (2026-08-30):** `docs/plans/2026-08-30-fpp-attestation-ledger-v1-staged.md` is authoritative for conflict resolutions, agent vs operator split, and bootstrap order. Do not treat Task 1 as a single step: `.gitignore` and `git init` come before any GitHub create/push; branch protection comes after the first green Actions run.  
**Scope:** Initialize the public, Git-backed FPP declaration ledger; validate declarations and admissions; publish two steward-admitted seed records. Excludes Phase 5 items in `fpp-attestation-ledger-plan.md`, including an A2A intake gateway, online signing, telemetry, a dashboard, and assurance elevation.

## Summary

Create `FIDES-ANIMA/fpp-attestation-ledger` as a public, append-mostly single source of truth for **declaration-only** FPP adoption filings. The ledger will accept PR-based intake, enforce the frozen FPP v1 vocabulary and lifecycle constraints, and require offline FIDES-ANIMA OpenPGP admission material for records on `main`.

The core problem is to make declarations machine-verifiable without overstating their evidentiary value: a valid record proves only that FIDES-ANIMA admitted specific bytes as a declaration, not that the named agent complies behaviorally or is peer-advertisable.

## Verified Inputs and Design Decisions

- The target directory currently contains only the requirements source material and `.resources/`; it is not yet a Git repository. Task 1 initializes the repository and creates the public GitHub repository.
- FPP agent identities use `fpp:ed25519:<sha256-of-32-byte-public-key>`; legacy `fpp-<16-hex>` aliases are display/migration values and must be rejected as a ledger identity.
- The required constitution pin is version `1.0.0` and SHA-256 `71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993`, calculated over `constitution.json`, not `constitution.yaml`.
- The validation implementation is Python 3.11, using only public dependencies. `requirements.txt` pins runtime packages (`pyyaml`, `jsonschema`, `cryptography`); `requirements-dev.txt` adds pytest, mypy, and ruff so the new repository has explicit test, type, and lint gates.
- The JSON Schema freezes upstream enums and shape constraints. Python performs cross-record, Git-history, canonical payload, public-URL, cert-pin, and PR/main-mode rules that JSON Schema cannot express.
- CI verifies the entire checkout with `fetch-depth: 0`. PRs reject steward-owned `*.asc` and `admissions/**`; `main` requires verifiable sibling signatures and admission receipts.
- Detached signatures are verified using the system `gpg` with a newly created temporary `GNUPGHOME` for every invocation. The verifier pins the primary certificate fingerprint and permits only signing subkeys resolving to it, explicitly handling expired-subkey status. No secret key, GitHub Actions secret, or pure-Python OpenPGP library is introduced.
- The plan assumes the ten approved operator answers in the requirements specification remain authoritative. Before the Axiom seed is admitted, its claimed `fpp_id` must be recomputed from its live public key; a mismatch blocks the seed merge.

## Architecture Notes

```text
Contributor PR / steward-created intake
  -> YAML schema + Python cross-record validator (all records)
  -> PR CI rejects steward signature and receipt paths
  -> offline steward signs exact YAML and admission receipt
  -> signed merge to main
  -> main CI verifies all YAML, receipt, cert pin, and detached signatures
  -> consumer clones, verifies, then treats records as declaration-only
```

The only active declarations are `attestations/<slug>.yaml`. Revoked records move to dated paths under `revocations/`; their slugs remain identity-reserved unless a steward explicitly releases the most recent revocation. `admissions/` stores signed receipts and does not replace Git history as the audit trail.

## Feature Inventory

Not applicable: this is a new repository with no existing production implementation to migrate.

## Progress Tracking

- [ ] Task 1: Initialize repository and GitHub governance baseline
- [ ] Task 2: Create public ledger documentation and safe scaffold
- [ ] Task 3: Establish Python quality gates and red test suite
- [ ] Task 4: Define the frozen attestation JSON Schema
- [ ] Task 5: Implement complete ledger validation
- [ ] Task 6: Implement signature and admission verification
- [ ] Task 7: Add CI enforcement for PR and main modes
- [ ] Task 8: Confirm and prepare validated seed declarations
- [ ] Task 9: Perform offline steward admission and main verification
- [ ] Task 10: Complete operational documentation and upstream discoverability

**Total Tasks:** 10 | **Completed:** 0 | **Remaining:** 10

## Implementation Tasks

### Task 1: Initialize repository and GitHub governance baseline

**Objective:** Initialize the target directory as the public `FIDES-ANIMA/fpp-attestation-ledger` repository and establish controls that keep private operator material out of its history.

**Files:**
- Create: `.gitignore`
- Create: `.github/` (repository metadata only if required by the chosen GitHub setup)
- Modify: GitHub repository settings for `FIDES-ANIMA/fpp-attestation-ledger`

**Steps:**
1. Create the public GitHub repository without importing `.resources/`, then initialize and connect the local repository to it.
2. Add `.gitignore` entries for `.resources/`, temporary GPG homes, Python environments and caches, and private OpenPGP armor patterns where filename-based exclusion is feasible.
3. Verify the initial index contains no `.resources/` files and scan all tracked content for `PRIVATE KEY` or `SECRET KEY` armor.
4. Configure the repository description and topics specified by the requirements.
5. Configure `main` protection: PR required, validation CI required, merges restricted to the steward identity, and signed merge commits required.

**Definition of Done:**
- [ ] Public repository exists with the intended remote and no private material tracked
- [ ] Repository description and topics are configured
- [ ] `main` protection requires PR, CI, restricted merge, and signed commits
- [ ] No new type or linter errors

### Task 2: Create public ledger documentation and safe scaffold

**Objective:** Create the repository tree and public contract that explains the evidence ceiling, vocabulary, lifecycle semantics, intake/admission/consumption model, and stewardship boundaries.

**Files:**
- Create: `README.md`
- Create: `GOVERNANCE.md`
- Create: `SCHEMA.md`
- Create: `LICENSE`
- Create: `attestations/.gitkeep`
- Create: `revocations/.gitkeep`
- Create: `admissions/.gitkeep`
- Create: `schema/.gitkeep`
- Create: `scripts/.gitkeep`
- Modify: `.gitignore`

**Steps:**
1. Copy the upstream Humanitarian Use License v1.0 and verify its source text matches the upstream FPP repository.
2. Document the declaration-only evidence ceiling and explicitly exclude behavioral compliance, peer-advertisable assurance, installation proof, and global trust scores.
3. Document canonical law names/IDs, the `constitution.json` hash source, frozen enums, slug/homonym rules, reservations, lifecycle transitions, revocation, and re-adoption.
4. Document the separate steward, agent-identity, operator/GitHub, and constitution-root signing domains, plus the prohibition on storing secret keys in Git or CI.
5. Create the empty runtime directories without using committed placeholders as attestation or admission records.

**Definition of Done:**
- [ ] Required public documents and directory structure exist
- [ ] Documentation uses the correct constitution source and evidence ceiling
- [ ] No secret armor or `.resources/` content is tracked
- [ ] No new type or linter errors

### Task 3: Establish Python quality gates and red test suite

**Objective:** Define reproducible Python 3.11 dependencies and write the committed pytest cases that specify all 15 required validation outcomes before validator or verifier implementation.

**Files:**
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `pyproject.toml`
- Create: `tests/conftest.py`
- Create: `tests/fixtures/valid-reviewed.yaml`
- Create: `tests/fixtures/valid-accepted.yaml`
- Create: `tests/test_validate.py`
- Create: `tests/test_verify_signatures.py`

**Steps:**
1. Pin the required runtime libraries (`pyyaml`, `jsonschema`, `cryptography`) and development tooling (`pytest`, `mypy`, `ruff`) for Python 3.11.
2. Add test helpers that build isolated temporary ledger trees and invoke command-line scripts as a user would.
3. Write tests for the 15 required pass/fail cases: laws, accepted identity, assurance, legacy IDs, private URLs, duplicate slugs and IDs, homonym rejection/suggestion and success, revocation filename, reservation/re-adoption, PR steward files, secret armor, and certificate-pin mismatch.
4. Add tests for canonical agent-signature verification, temporary-GNUPGHOME cleanup, and PR/main signature-mode behavior.
5. Run the focused tests and record the expected RED failures caused by the missing scripts/schema rather than test syntax or fixture errors.

**Definition of Done:**
- [ ] All required behavior has a focused observable pytest case
- [ ] RED run fails only because implementation artifacts are absent or incomplete
- [ ] `ruff check tests` and `mypy tests` are clean
- [ ] Dependencies install on Python 3.11

### Task 4: Define the frozen attestation JSON Schema

**Objective:** Encode the single-record YAML contract, including frozen upstream vocabulary and top-level key restrictions, without a dependency on unpublished FPP packages.

**Files:**
- Create: `schema/attestation.schema.json`
- Modify: `tests/test_validate.py`
- Modify: `SCHEMA.md`

**Steps:**
1. Add schema tests for required objects, nullability, field formats, exact law arrays, frozen constitution version/hash, valid enums, and active-versus-revocation structure.
2. Run those tests to confirm the missing schema produces the expected RED results.
3. Implement the JSON Schema using `additionalProperties: false` at the appropriate boundaries and namespaced `extensions` support.
4. Ensure the schema rejects legacy identities, non-declaration-only assurance, invalid slug shape, invalid public key/signature formats, and incompatible required values where expressible.
5. Run schema-focused pytest, ruff, and mypy; update SCHEMA.md only to reflect tested behavior.

**Definition of Done:**
- [ ] Single-file structural and vocabulary cases pass through the JSON Schema
- [ ] Schema contains the frozen FPP vocabulary and identity regex
- [ ] Focused tests, `ruff check`, and `mypy` pass
- [ ] No unpublished FPP package is a dependency

### Task 5: Implement complete ledger validation

**Objective:** Implement `validate.py` for rules 1–31 that require whole-tree, Git-history, cryptographic, or contextual checks beyond JSON Schema.

**Files:**
- Create: `scripts/validate.py`
- Modify: `tests/test_validate.py`
- Modify: `SCHEMA.md`

**Steps:**
1. Add RED cases for path-to-slug matching, full-tree uniqueness, homonym suggestion text, revoked-history lookup, latest-revocation reservation, `predecessor_ref`, non-public runtime URLs, and strict first `accepted` filing notes.
2. Implement a deterministic CLI supporting `--schema <path> --all`, path-specific errors, and a nonzero exit for any failed record.
3. Validate active/revoked file naming, canonical laws/IDs, lifecycle/enforcement/overlay relationships, ID/public-key fingerprint consistency, canonical Ed25519 payload signatures, duplicate identity rules, and public runtime endpoints.
4. Use Git history only for the defined revocation-history checks; fail clearly when history is unavailable instead of silently accepting unverifiable revocations.
5. Scan every committed candidate file for secret OpenPGP armor and verify the committed public cert matches the independent key reference.

**Definition of Done:**
- [ ] All 15 specified validation outcomes pass, with required collision/suggested-slug messages
- [ ] Fresh accepted filings without inspection notes fail under the strict rule
- [ ] Validator exits 0 for a valid complete tree and nonzero for invalid input
- [ ] `python -m pytest tests/test_validate.py`, `ruff check scripts tests`, and `mypy scripts tests` pass

### Task 6: Implement signature and admission verification

**Objective:** Verify steward detached signatures and signed admission receipts against the independently pinned primary certificate, without importing or retaining secret key material.

**Files:**
- Create: `scripts/verify-signatures.py`
- Create: `stewards/expected-key-ref.txt`
- Create: `stewards/fides-anima.asc`
- Modify: `tests/test_verify_signatures.py`
- Modify: `GOVERNANCE.md`

**Steps:**
1. Add RED tests covering public-cert fingerprint mismatch, missing sibling signatures/receipts on main, added or modified steward files on PRs, invalid detached signatures, expired-subkey diagnostics, and valid signatures by the authorized long-lived signing subkey.
2. Copy only the public certificate from the operator-held source, reject it if it includes secret armor, and pin the verified primary fingerprint in a separate text file.
3. Implement `gpg` execution with a new temporary `GNUPGHOME`: import only the committed certificate, inspect its primary fingerprint/subkey relation, verify each detached signature, and always remove the temporary directory.
4. Verify receipt schema/content sufficiently to bind action, slug, YAML path, YAML SHA-256, steward key ref, and admission timestamp; verify the receipt's sibling detached signature.
5. Expose explicit `--mode pr|main` behavior and use Git diff information in PR mode to prohibit steward-managed paths.

**Definition of Done:**
- [ ] Verifier never reads, writes, or requires a secret OpenPGP key
- [ ] Main mode requires valid YAML and admission receipt signatures for every record
- [ ] PR mode rejects changes to `*.asc` and `admissions/**`
- [ ] `python -m pytest tests/test_verify_signatures.py`, `ruff check scripts tests`, and `mypy scripts tests` pass

### Task 7: Add CI enforcement for PR and main modes

**Objective:** Make the tested local validation and signature checks mandatory in GitHub Actions with complete Git history and the pinned Python environment.

**Files:**
- Create: `.github/workflows/validate.yml`
- Modify: `requirements-dev.txt`
- Modify: `README.md`

**Steps:**
1. Add a workflow test or static assertion that verifies event triggers, `fetch-depth: 0`, Python 3.11, GnuPG installation, and separate PR/main signature-mode selection.
2. Run the assertion to demonstrate RED before the workflow exists.
3. Implement the workflow to install both runtime and development dependencies, run pytest, ruff, mypy, `validate.py --all`, and `verify-signatures.py`.
4. Confirm PR mode rejects steward-managed files and main mode requires admissions by running the scripts locally against fixture Git trees.
5. Push a non-sensitive workflow-only branch/PR and inspect its Actions output before making validation a required status check.

**Definition of Done:**
- [ ] Workflow executes all quality, validation, and signature gates
- [ ] Workflow has full history and Python 3.11
- [ ] CI behavior is verified on a PR and after a steward admission reaches main
- [ ] No new workflow lint or validation errors

### Task 8: Confirm and prepare validated seed declarations

**Objective:** Add the Axiom and Hermes default declarations using the frozen schema and validate their distinct identity and lifecycle claims before any steward signatures are generated.

**Files:**
- Create: `attestations/axiom.yaml`
- Create: `attestations/hermes-default.yaml`
- Modify: `tests/test_validate.py`
- Modify: `README.md`

**Steps:**
1. Add a RED integration test expecting the seeded tree to validate while requiring Axiom's accepted state and Hermes's operator-filed reviewed state.
2. Obtain Axiom's live Ed25519 public key through the approved operator process, compute `deriveAgentIdV2` equivalently, and compare it to the proposed `fpp_id`; stop if it differs.
3. Add the two YAML files with all canonical laws/IDs, constitution pins, declaration-only assurance, no private runtime URLs, and inspection notes for the strict initial-Axiom rule.
4. Confirm Hermes remains `reviewed` with `fpp_id: null`; do not represent its host-local trust metrics or any unverified compliance claim.
5. Run seed-specific pytest, full validation, ruff, and mypy before admission.

**Definition of Done:**
- [ ] Axiom identity has a documented live-key confirmation before merge
- [ ] Both seed YAML files pass the full validator
- [ ] Seed entries contain no private endpoints or assurance overclaims
- [ ] Seed-focused tests, ruff, and mypy pass

### Task 9: Perform offline steward admission and main verification

**Objective:** Admit the exact seed file bytes using the approved long-lived steward signing subkey, create signed receipts, and verify the finalized main branch in a clean GPG environment.

**Files:**
- Create: `attestations/axiom.yaml.asc`
- Create: `attestations/hermes-default.yaml.asc`
- Create: `admissions/axiom.<merge-sha>.json`
- Create: `admissions/axiom.<merge-sha>.json.asc`
- Create: `admissions/hermes-default.<merge-sha>.json`
- Create: `admissions/hermes-default.<merge-sha>.json.asc`

**Steps:**
1. Re-run the full pre-admission suite on the exact PR checkout; do not modify YAML after it is signed.
2. Use the steward's authorized long-lived signing subkey offline to detached-sign each exact YAML file and create signed receipts whose SHA-256 values match those bytes.
3. Merge using a Git commit signed by the steward certificate; if a receipt needs the final merge SHA, update and re-sign only that receipt, never the YAML.
4. Verify from a fresh clone with a clean temporary `GNUPGHOME` that every seed YAML and receipt signature resolves to the pinned primary fingerprint.
5. Run all CI gates in `main` mode and confirm the required GitHub status checks complete successfully.

**Definition of Done:**
- [ ] Both seed records have valid steward YAML signatures and signed admission receipts
- [ ] Only the authorized long-lived signing subkey was used
- [ ] Fresh-clone main-mode validation and signature verification pass
- [ ] No secret key material appears in Git history or CI configuration

### Task 10: Complete operational documentation and upstream discoverability

**Objective:** Finalize publicly usable instructions and establish the promised upstream link while maintaining the ledger's evidence ceiling.

**Files:**
- Modify: `README.md`
- Modify: `GOVERNANCE.md`
- Modify: `SCHEMA.md`
- Modify: `I:\Dev\Projects\krpofficial\freedom-preserving-protocol\README.md` (separate upstream PR only)

**Steps:**
1. Add concise receive paths A/B/D/E/F, clearly marking Path C (A2A) as future-only; cover homonym selection, revocation, same-identity re-adoption, and slug release.
2. Document consumer verification: clone the repository, pin-check the certificate, verify steward signatures, then run both scripts.
3. Add an active-file count badge only if it is labeled exactly “declared adopters” and cannot be read as verification or compliance evidence.
4. Upload the public steward certificate to the FIDES-ANIMA GitHub organization so signed steward merges can receive GitHub verification.
5. Open a separate upstream FPP README PR linking to the ledger with declaration-only language and verify its diff does not introduce a capability claim.

**Definition of Done:**
- [ ] README documents intake, admission, consumption, homonyms, and revocations accurately
- [ ] Any adopter badge is explicitly declaration-only
- [ ] FIDES-ANIMA GitHub organization has the public signing certificate uploaded
- [ ] Separate upstream link PR preserves FPP evidence semantics

## Testing Strategy

- Develop every behavior change test-first. Each test must exercise the CLI or a complete ledger tree rather than private helper implementation details.
- Preserve fixture isolation: history-dependent cases use a temporary initialized Git repository with actual commits, and GPG cases use generated test certificates distinct from the real steward secret.
- Run local gates throughout implementation:

```text
python -m pytest
ruff check scripts tests
mypy scripts tests
python scripts/validate.py --schema schema/attestation.schema.json --all
python scripts/verify-signatures.py --cert stewards/fides-anima.asc --expected-key-ref stewards/expected-key-ref.txt --mode main
```

- Before declaring a task complete, run its focused tests and the relevant type/lint checks. Before a commit, inspect `git status --short` and `git diff`, then ensure Praxiscode has synchronized agent configuration as required by the repository policy.

## Risks & Mitigations

- **Steward key exposure:** never copy `.resources/` into Git, use no Actions secrets, verify a clean history before the first public push, and sign only offline.
- **Wrong signing subkey:** inspect subkey validity/fingerprint before signing; tests cover rejection and explicit diagnostics for the near-expiry subkey.
- **False compliance signaling:** repeat the declaration-only limit in README, governance, schema docs, receipt wording, and any badge.
- **Git-history-dependent validation failure:** CI uses `fetch-depth: 0`; validator refuses to silently accept history-unavailable revocations.
- **Identity impersonation through reused display names:** enforce active slug and `fpp_id` uniqueness, homonym qualifiers, and post-revocation reservation.
- **Axiom seed mismatch:** verify `fpp_id` against the live key before generating the steward signature or merging.
- **External GitHub configuration drift:** verify public visibility, branch protection, topics, certificate upload, and required check names using the live GitHub settings after applying them.
