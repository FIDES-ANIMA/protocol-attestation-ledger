# FPP Attestation Ledger v1 — Reconciliation and Staged Plans

**Status:** Ready for development; admission-workflow proof required before CI / branch-protection freeze  
**Created:** 2026-08-30  
**Scope freeze:** `requirements/2026-08-27-1319-fpp-attestation-ledger-init/06-requirements-spec.md`  
**Baseline schema / rules:** `fpp-attestation-ledger-plan.md` (superseded where this file says so)  
**Task-level Definitions of Done:** `docs/plans/2026-08-27-fpp-attestation-ledger-v1.md`  
**Live actuals:** 2026-09-08 — local directory is not a Git repository; `gh repo view FIDES-ANIMA/fpp-attestation-ledger` reports that the repository does not exist; the short-lived signing subkey has expired.

This document reconciles the requirements spec with the implementation plan, then splits work into two tracks that must interleave:

- **Development** — schema, validators, tests, CI YAML, public docs. An agent can do this. TDD is mandatory.
- **Implementation** — GitHub repo, branch protection, live Axiom identity confirmation, offline OpenPGP admission, steward-account GPG upload, upstream discoverability. A human operator must perform or authorize the gated steps.

Do not treat either source document as a linear script. Plan §8 phases and the 2026-08-27 ten-task list remain valid as checklists; this file is the sequencing overlay.

---

## 0. Authority

| Rank | Document | Wins on |
|------|----------|---------|
| 1 | This file §§1.7, 4, 5, 7 | The four corrective contracts: independent admission state, authenticated authorship, structured lifecycle evidence, and protected-branch admission |
| 2 | `06-requirements-spec.md` | Remaining v1 scope, operator decisions FR1–FR6 / TR1–TR5, acceptance criteria, what is out of scope |
| 3 | `fpp-attestation-ledger-plan.md` | Repo tree and schema/rule detail only where not superseded by this file |
| 4 | `docs/plans/2026-08-27-fpp-attestation-ledger-v1.md` | Per-task files, steps, and Definitions of Done — **not** GitHub/CI bootstrap order |

If a later FPP release changes a cited hash, enum, or law name, update plan §0 in the same change as the schema. Until then the constitution pin stays `1.0.0` / `71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993`.

The older documents remain useful inputs, but their steward-revocation, optional-authorship, free-text-inspection, and two-mode CI rules are explicitly superseded below.

---

## 1. Reconciliation

### 1.1 What already agrees

The product is the **authoritative record of FIDES-ANIMA-admitted declarations**: a public Git ledger of declaration-only FPP adoption filings and the Institute's independent decisions to admit, dispute, correct, withdraw, or reinstate publication. It is not the authority over an agent's constitutional commitment. Every ledger entry is `attestation.assurance: declaration-only`. Admission is not agent consent, behavioral compliance, or `peer-advertisable` assurance.

Shared invariants that implementation must not weaken:

- Evidence ceiling in README, GOVERNANCE, SCHEMA, admission events, and any badge.
- Four signing domains stay distinct (ledger-steward OpenPGP, agent Ed25519, operator/GitHub, FPP constitution-root).
- Python 3.11 validators; frozen enums in `attestation.schema.json`; no unpublished `@ovrsr/fpp-*-core` packages.
- `.resources/` is operator-held source and is git-ignored; published cert is `stewards/fides-anima.asc`.
- Secret OpenPGP material never enters git, CI, or GitHub Actions secrets.
- CI validates the **entire** tree with `fetch-depth: 0`.
- Contributor **intake PRs** reject steward `*.asc` and `admissions/**`; steward **admission PRs** must contain them and validate the exact candidate tree later promoted to `main`.
- v1 ships plan §8 Phases 1–4. Phase 5 stays out of scope.

### 1.2 Conflicts and resolutions

| ID | Plan (`fpp-attestation-ledger-plan.md`) | Spec (`06-requirements-spec.md`) | Resolution (authoritative) |
|----|------------------------------------------|----------------------------------|----------------------------|
| C1 | §5 CI snippet: `pip install pyyaml jsonschema` (unpinned, no `cryptography`) | TR4: committed pinned `requirements.txt` = `pyyaml`, `jsonschema`, `cryptography`; CI pins Python 3.11 | **Spec.** Workflow is `pip install -r requirements.txt` (and `-r requirements-dev.txt` for pytest). Plan §5 snippet is superseded. `cryptography` is required for rules 14 and 31. |
| C2 | §4: GOVERNANCE.md may document a ledger-specific relaxation that a steward can accept a first `accepted` filing if `notes` records inspection; default **strict** | FR5: CI **enforces** strict | **Corrected contract.** Free text is not machine evidence. A first `accepted` filing requires structured inspection and acceptance evidence with constitution hash, timestamp, actor, and record reference. CI validates structure and consistency; the steward judges context. No relaxation or notes-based bypass exists. |
| C3 | §8 Phase 2: 15 local must-pass / must-fail checks | TR5: those 15 cases are a committed pytest suite, TDD, executed by CI | **Spec.** The 15 cases are the minimum suite. Additional tests (FR5, expired-subkey diagnostics, GNUPGHOME cleanup) are required where the spec names them. |
| C4 | §8 Phase 1: create GitHub repo, then add files | FR1: initialize the local directory as the git repo and push | **Both, sequenced.** `git init` + `.gitignore` **before** any add/commit. Create an empty public GitHub repo. First push only after the ignore file is in the initial commit. Never `gh repo create` from a tree that can add `.resources/`. |
| C5 | §5 `validate.py` “implements rules 1–31” | Data flow splits schema/uniqueness (validate) from PR/main signature mode (verify-signatures) | **Superseded.** The original 31 are a baseline, not a closed list. `validate.py` also enforces the contracts in §1.7; `verify-signatures.py` has `intake`, `admission`, and `main` modes. |
| C6 | README / Path A–F including Path D (trusted-agent branch + PR) | Acceptance criteria list paths A/B/E/F only | **Document A, B, D, E, F.** Path C remains future (Phase 5). Path D is in the plan and is not excluded by the spec; it still requires steward admit. |
| C7 | Phase 1 checklist includes `stewards/*.asc` with the scaffold | 2026-08-27 task plan copies the cert in Task 6 (signature work) | **Copy the public cert in Development D1.** Pin tests and rule 29 cannot wait for admission. Copy public armor only; refuse secret armor. |
| C8 | Branch protection “PR + CI required” listed in Phase 1 | CI workflow is Phase 2 | **Implementation I2 after first green Actions run.** You cannot require a check that has never run. Create the public repo first with no required status (or status optional); add the required check name after the workflow exists. |
| C9 | Seed files appear as soon as Phase 3 | `main` mode requires `.asc` + receipts for every YAML | **Empty `attestations/` on first `main` is valid.** Validate unsigned declaration bytes in an intake PR, then construct a steward admission PR containing those unchanged bytes plus signatures/events. Only the exact green, steward-signed admission head may be promoted to `main`. |
| C10 | `requirements-dev.txt`, mypy, ruff in the 2026-08-27 task plan | TR4 names only runtime pins; acceptance criteria do not mention ruff/mypy | **Keep as development gates, not spec acceptance blockers.** CI **must** run pytest + `validate.py --all` + `verify-signatures.py`. ruff/mypy are recommended and may run in CI; a red ruff run does not by itself fail spec AC. |
| C11 | Steward can revoke any filing by setting `adoption.lifecycle_state: revoked` | Institute may remove a fraudulent or harmful filing from its admitted set | **Separate axes.** A steward may withdraw ledger admission, but MUST NOT thereby alter constitutional lifecycle. Adoption withdrawal requires evidence from the agent or reporting operator under §1.7.1. |
| C12 | `fpp_id` is required for `accepted`, while public key and agent signature are optional | A claimed identifier is not authenticated authorship | **Explicit provenance.** Every declaration is `agent-signed` or `operator-reported`. Only a valid agent signature authenticates agent authorship; a steward signature authenticates publication only. |
| C13 | First acceptance is inferred from prose in `attestation.notes` | Lifecycle evidence must be mechanically enforceable | **Structured evidence.** Inspection, acceptance, transition, and predecessor data are typed fields. CI checks transitions, immutable identity, and history preservation. |
| C14 | PR mode forbids admission artifacts but final `main` requires them | Required-PR protection cannot merge the unsigned intake tree as-is | **Three-mode workflow.** Intake PRs are never merged. A steward builds a signed admission branch, admission-mode CI validates its exact head, and an authorized ruleset bypass fast-forwards that same tested head to `main`. The procedure must pass the §7 proof before I2 freezes protections. |

### 1.3 Spec extras the original plan did not freeze

These are in-scope for v1 because the spec accepted them:

| Extra | Source | Where it lands |
|-------|--------|----------------|
| Committed pytest suite for the 15 Phase-2 cases | TR5 | Development D2, CI D6 |
| `cryptography` for Ed25519 verify + pubkey→fingerprint | TR4, context finding 3 | `requirements.txt`, rules 14 and 31 |
| System `gpg` + ephemeral `GNUPGHOME` (no pure-Python OpenPGP) | TR3 | `verify-signatures.py` |
| Sign **only** with the long-lived signing subkey (expires 2028-08-26) | TR2 | Implementation I5 operator procedure |
| Verifier accepts any signing subkey that resolves to the pinned **primary** fingerprint, and must handle expired-subkey GnuPG behavior explicitly | TR2 | Development D5 tests |
| SCHEMA.md and validator state that `constitution_hash` is SHA-256 of **`constitution.json`**, not `constitution.yaml` (`da58a4f3…` must not be cited) | TR1 | Development D1 / D3 / D4 |
| Strict first-filing of `accepted` without structured inspection and acceptance evidence fails CI | FR5 + AC | Development D2 + D4 |
| Axiom `fpp_id` confirmed against the live identity key (`deriveAgentIdV2`) before seed merge | FR3 + AC | Implementation I3 (operator gate) |

Signing policy and verify policy are different roles, not a conflict: the operator **creates** signatures only with the long-lived subkey; the verifier may accept a historical signature from another signing subkey of the pinned primary if it was valid at the recorded signing time.

The 2026-09-08 public-cert inspection resolves the long-lived signing-subkey fingerprint as `0DCD3952B0BA0130E02A5FC70DBBE66FEC6D0C67`. New declaration/event artifacts and admission Git commits MUST use that subkey; matching only the primary fingerprint is insufficient for new admissions.

### 1.4 Plan extras the spec did not name, still in v1

Kept because the spec says the plan is authoritative for schema/rule detail:

- Slug grammar, homonym occupancy, post-adoption-withdrawal reservation, `slug_released`.
- Canonical payload (RFC 8785-style JSON) for agent Ed25519 signatures.
- Append-only admission event shape and chain in §1.7.1.
- Declaration actions: `attest`, `amend`, `correct-declaration`, `withdraw-adoption`, `re-adopt`. Admission actions: `admit`, `mark-disputed`, `withdraw-admission`, `reinstate-admission`, `correct-admission`, `resolve-dispute`, `slug-release`.
- Overlay / enforcement coupling (`verification_failed` blocks `accepted`; `prompt-only` + `accepted` requires `runtime_degraded`; `none` cannot be `accepted`).
- Seed identity/content inputs in plan §7, rewritten to the corrected schema after I3 confirms Axiom’s `fpp_id`.

### 1.5 Explicitly out of scope (Phase 5)

Do not schedule, stub-implement, or “while we’re here” any of:

- A2A attestation gateway (Path C)
- CI-held or Actions-held signing key
- Automated merge-SHA fill that requires a private key in CI
- Elevation to `peer-advertisable`
- Health-check / telemetry / verify-install probes
- Public dashboard / GitHub Pages
- Generated `registry.json` (optional later; validator scans the tree)
- Constitutional-amendment lineage (upstream amendments are still PROPOSED)

### 1.6 Actuals drift since the 2026-08-27 documents

Verified 2026-09-08:

1. **Short-lived signing subkey has expired.** Plan and spec described it as expiring 2026-08-29. D5 tests must treat expired-subkey GnuPG diagnostics as live behavior, not a future edge.
2. **No Git repository** in `I:\Dev\Projects\FIDES-ANIMA\fpp-attestation-ledger`.
3. **GitHub repository does not exist** (`gh repo view FIDES-ANIMA/fpp-attestation-ledger` → unresolved).
4. Working tree contains planning material only: `fpp-attestation-ledger-plan.md`, `requirements/`, `docs/plans/`, `.resources/`. The first commit must not include `.resources/`.

### 1.7 Corrected v1 contracts

#### 1.7.1 Constitutional lifecycle and admission lifecycle are independent

`adoption.lifecycle_state` records what the declaration claims about the agent. It changes only through an authorized declaration action. FIDES-ANIMA's decision to publish that declaration is a separate, derived `admission_status`.

Admission events are immutable, steward-signed JSON files named `admissions/<slug>.<record-sha256>.<sequence>.json`, where `sequence` starts at `0001` and increases without gaps. Each event contains:

- `schemaVersion`, `action`, `admissionStatus`, `reasonCode`, non-empty `reason`, and `occurredAt`
- `record.declarationId`, `record.version`, `record.path`, and lowercase SHA-256 `record.sha256` over exact file bytes
- `actor.type: steward` and the pinned `actor.keyRef`
- `request.sourceType`, `request.sourceRef`, and `request.requestedBy`; public evidence uses hash-bearing `{uri, sha256}` references when immutable bytes are available
- `authority.basis`, normalized `authority.principal`, and `authority.evidenceRef`
- for declaration actions, `review.intakePr`, `review.headSha`, `review.checkRun`, and `review.declarationHashes`
- `previousEvent: {path, sha256}` for every event after `0001`, hashing exact prior JSON bytes
- `correctionRef: {declarationId, version, path, sha256, admissionEvent: {path, sha256}}` when status is `corrected`; both hashes cover exact referenced bytes

The steward signature over declaration bytes is content-addressed as `admissions/<slug>.<record-sha256>.record.asc`; each event signature is its JSON path plus `.asc`. These files are append-only, so amendment never overwrites the signature for an earlier declaration version.

Every declaration also has immutable `attestation.declaration_id` and positive integer `attestation.version`. Version 1 has no predecessor. Each later version increments by one and has `attestation.predecessor_record: {path, sha256}`. The lineage head is the unique highest valid version. The **current admitted set** contains only lineage heads whose latest admission event is `admitted` and whose current YAML exists under `attestations/` or `revocations/`; historical predecessor events remain true historical facts but are not counted again. A fork or unrelated competing claim uses a new `declaration_id`.

Allowed admission statuses are `admitted`, `disputed`, `withdrawn`, and `corrected`. Allowed event transitions are:

```text
(none)    --admit--------------> admitted
admitted  --mark-disputed------> disputed
admitted  --withdraw-admission-> withdrawn
disputed  --resolve-dispute----> admitted | withdrawn
withdrawn --reinstate-admission> admitted
admitted | disputed --correct-admission--> corrected
withdrawn | corrected --slug-release-----> same status, with `slugReleased: true`
```

A steward action changes only this admission chain. It MUST preserve the declaration bytes and `adoption.lifecycle_state`. A constitutional withdrawal instead creates an authorized `withdraw-adoption` declaration, sets lifecycle to `revoked`, and preserves its predecessor. Steward suspicion, fraud review, impersonation, harmful content, or registry error are grounds to dispute or withdraw **admission**, not evidence that the agent withdrew acceptance.

Disputes are received through a public GitHub issue or the documented out-of-band path; the request itself is not ledger state. The steward records the requester and public evidence references, marks the admission `disputed` when warranted, and resolves it by an append-only event. A declaration correction is an intake action producing the next declaration version: admit the new record, append `correct-admission` to the old record, and require reciprocal hash-bearing links between the new `predecessor_record` and old event's `correctionRef`. Preserve both histories.

The current public admitted set is computed from the latest valid event for each declaration, not from directory membership alone.

#### 1.7.2 Claimed identity and authenticated authorship are explicit

Every declaration has `attestation.authorship: agent-signed | operator-reported`.

- `agent-signed` requires `agent.fpp_id`, `agent.public_key_hex`, and a valid `attestation.signature` over the canonical declaration payload. The public key MUST fingerprint to `fpp_id`. This authenticates authorship of those bytes, not behavior.
- `operator-reported` requires `attestation.filing: operator` and `operator.contact`. An `accepted` lifecycle value means only that the named operator reports acceptance. Any `fpp_id` is a claimed identifier until an agent signature authenticates it.
- `attestation.filing: self` is valid only with `authorship: agent-signed`.
- A steward OpenPGP signature authenticates the admission event and admitted bytes. It never upgrades `operator-reported` to agent-signed or proves agent consent.

For filing authority, intake CI verifies an agent signature regardless of who transports the PR. For the GitHub path, `operator.contact` MUST be `github:<lowercase-login>`. The PR author and actor on the final `opened`/`synchronize` event that produced the reviewed head MUST match that login after lowercasing; for a fork, the head-repository owner MUST also match, while a base-repository branch must be under the operator's restricted `intake/<login>/` prefix. The authority record binds the event ID and exact head SHA. Any head change invalidates prior authority/check evidence and requires a new matching event. Workflow reruns do not supply authority. Other URI/email contacts use out-of-band intake. The initial signed admission event durably records the intake source, authenticated principal, reviewed head/check, exact declaration hashes, and authority evidence. Amendments and adoption withdrawals require the same authority class as the declaration they change. Conversion from operator-reported to agent-signed is a new signed declaration correction, not an in-place provenance edit.

Uniqueness is assurance-aware. Duplicate **authenticated** `fpp_id` occupancy fails. Operator-reported identifiers do not reserve an authenticated identity and cannot block a later valid agent-signed filing; competing claims remain visibly operator-reported and use disambiguated slugs. Slug occupancy remains separate and may be changed only through the admission dispute/correction and explicit slug-release process.

#### 1.7.3 Lifecycle evidence and history rules are structural

An adoption transition contains typed `adoption.transition` data: `from`, `to`, `occurred_at`, `actor`, and `predecessor_ref`. A first `accepted` declaration also contains:

- `adoption.evidence.inspection`: `record_ref`, `constitution_hash`, `inspected_at`
- `adoption.evidence.acceptance`: `record_ref`, `constitution_hash`, `accepted_at`

Both hashes must equal `adoption.constitution_hash`; inspection must not postdate acceptance; acceptance must not postdate the transition. CI validates presence, types, ordering, hash equality, the upstream transition matrix, and authority evidence. It does not infer evidence from `notes` or judge whether an external reference is persuasive; that contextual judgment belongs to steward review and is disclosed as such.

Git-aware validation rejects an impossible transition; an `amend` that changes `agent.slug`, `agent.fpp_id`, `agent.public_key_hex`, provenance, or operator identity; deletion of a declaration without an authorized replacement/move; and any mutation or deletion under `revocations/` or `admissions/`. An active declaration may change only through an authorized, predecessor-linked amendment whose prior blob remains in Git history. Adoption withdrawal and re-adoption must retain predecessor links. Identity rotation or provenance upgrade uses a new correction-linked record.

#### 1.7.4 Admission workflow contract

There are three verifier modes selected from trusted GitHub event context, never from contributor-controlled content:

1. `intake`: declaration changes only; rejects steward `*.asc` and `admissions/**`; checks schema, lifecycle, history, authorship, and filing authority.
2. `admission`: allowed only for `admission/*` branches in the base repository and the configured steward actor; requires all steward signatures/events and validates the complete candidate tree exactly as `main`.
3. `main`: validates the complete published tree and all admission chains.

An intake PR is review input and is never merged. The steward constructs an admission branch from current `main`, applies the reviewed intake diff without changing declaration bytes, adds signed artifacts, and creates one pinned-key-signed admission head. Admission CI must pass on that exact SHA. A narrowly scoped steward ruleset bypass then fast-forwards `main` to that SHA; force-push and a non-fast-forward update are forbidden. `main` CI revalidates the same tree.

This path applies equally to initial attestations, amendments, declaration corrections, adoption withdrawals, admission withdrawals, dispute marking/resolution, reinstatements, slug releases, and re-adoptions. D6 and §7 must prove every action class in a temporary git fixture and then through the disposable/live proof split before I2 makes the checks required.

---

## 2. Scope freeze (v1 done when)

Mapped from spec Acceptance Criteria. A stage may not be marked complete unless its exit criteria below are met.

| AC | Statement | Proven by |
|----|-----------|-----------|
| AC1 | Public repo `FIDES-ANIMA/fpp-attestation-ledger` with plan §2 tree, HUL v1.0, no `.resources/` or secret armor anywhere in history | I1 + history scan |
| AC2 | `python scripts/validate.py --mode main --schema schema/attestation.schema.json --all` exits 0 on the seeded tree; pytest covers the original 15 cases plus every corrected-contract case in D2 | D4 + D7 + I5 |
| AC3 | CI on intake PRs, admission PRs, and `main` with `fetch-depth: 0`; intake mode forbids steward artifacts; admission and main modes verify the full tree, signatures, event chains, histories, and authority | D6 + I4 + I5 |
| AC4 | The committed cert matches the pinned primary fingerprint and contains the pinned long-lived signing subkey `0DCD3952B0BA0130E02A5FC70DBBE66FEC6D0C67`; new admission artifacts must use that subkey | D1 + D5 |
| AC5 | Both seeds admitted on `main` by promotion of the exact green, long-lived-subkey-signed admission head; artifacts verify in a clean `GNUPGHOME`; the live workflow proof demonstrates branch-protection behavior | I2 + I5 + I6 + I7 |
| AC6 | Axiom `fpp_id` confirmed against the live key before seed admission; authorship of the exact bytes is reported separately | I3 |
| AC7 | A fresh `accepted` filing without structured inspection and acceptance evidence fails CI; notes cannot satisfy the rule | D2 + D4 + D6 |
| AC8 | README states the evidence ceiling, documents intake A/B/E/F (and D), consume steps, and labels counts as **currently admitted declarations** split by provenance | D8 |
| AC9 | Steward withdrawal changes only append-only `admission_status`; tests prove the declaration lifecycle and bytes remain unchanged and dispute/correction history remains visible | D2 + D4 + D5 |
| AC10 | Every declaration is visibly `agent-signed` or `operator-reported`; only the former reserves an authenticated `fpp_id`; filing-authority failures are rejected | D2 + D4 + I4 |

---

## 3. Track split

```text
Development (agent, TDD)                         Implementation (operator-gated)
-------------------------                        --------------------------------
D0  gitignore + git init                         I0  create empty public GitHub repo
D1  public contract + dirs + public cert         I1  first push (after D6)
D2  RED pytest (baseline + corrected contracts)  I2  prove workflow, then protect main
D3  declaration + admission-event schemas       I3  confirm Axiom fpp_id (live key)
D4  validate.py lifecycle/authorship/history     I4  intake PR for unsigned seeds
D5  verify-signatures.py + admission chains      I5  offline admission PR + promotion
D6  GitHub Actions workflow                      I6  fresh-clone consume verification
D7  seed YAML with explicit provenance           I7  steward-account GPG upload
D8  docs polish + provenance-aware counts        I8  upstream FPP README PR
```

**Hard gates the agent cannot close:**

| Gate | Who | Blocks |
|------|-----|--------|
| Org permission to create `FIDES-ANIMA/fpp-attestation-ledger` public | Operator | I0 |
| Axiom live Ed25519 → `deriveAgentIdV2` vs claimed `fpp_id`; agent signature if authorship will be `agent-signed` | Operator / Axiom | D7, I4, I5 |
| Offline long-lived signing subkey (expires 2028-08-26) | Operator | I5 |
| Upload public cert to the verified steward GitHub account | Operator | GitHub-verified admission commits (AC5) |
| Live proof of intake → admission → exact-SHA promotion under the queried ruleset | Operator | I2 protection freeze, I4, I5 |
| Pinned long-lived-subkey-signed admission commit | Operator | I5 |
| Fork/PR on `ovrsr/freedom-preserving-protocol` | Operator (`ovrsr` identity) | I8 |

---

## 4. Development plan

TDD rule for every behavior stage (D2–D6): write the failing pytest first, record RED, then implement the minimum that turns it GREEN. Tests invoke the CLI or a complete temporary ledger tree — not private helpers. GPG fixtures use generated test certificates, never the real steward secret. History-dependent cases use a temporary `git init` with real commits.

Quality commands (once D2 exists):

```text
python -m pytest
python scripts/validate.py --mode working --schema schema/attestation.schema.json --all
python scripts/verify-signatures.py --cert stewards/fides-anima.asc --expected-key-ref stewards/expected-key-ref.txt --expected-signing-subkey-ref stewards/expected-signing-subkey-ref.txt --mode main
```

Recommended (not spec-blocking): `ruff check scripts tests` and `mypy scripts tests`.

### D0 — Safety baseline and local Git

**Maps to:** FR1, plan §2 ignore rules, 2026-08-27 Task 1 (local half)  
**Depends on:** nothing  
**Operator needed:** no

**Do:**

1. Create `.gitignore` covering `.resources/`, virtualenvs, `__pycache__/`, `.pytest_cache/`, ephemeral `GNUPGHOME` directories, and obvious private-armor filenames.
2. `git init` in `I:\Dev\Projects\FIDES-ANIMA\fpp-attestation-ledger`.
3. Make the **first commit** `.gitignore` (and only files that cannot contain secrets). Confirm `git ls-files` has no `.resources/` and no `PRIVATE KEY` / `SECRET KEY` armor.
4. Leave planning markdown (`fpp-attestation-ledger-plan.md`, `requirements/`, `docs/plans/`) in the tree if they are public; they contain no secret armor. Do not add `.resources/`.

**Exit:** `git check-ignore -v .resources/FIDES-keys.txt` reports ignored; `git status` does not list `.resources/` as staged.

### D1 — Public contract and empty tree

**Maps to:** plan §8 Phase 1 (files), FR1 published cert, TR1 hash-source sentence, 2026-08-27 Task 2 + cert half of Task 6  
**Depends on:** D0  
**Operator needed:** no (copy public armor only)

**Create:**

- `LICENSE` — Humanitarian Use License v1.0, text matched to `ovrsr/freedom-preserving-protocol`
- `README.md` — purpose, evidence ceiling, constitution pin **from `constitution.json`**, five law names, pointer to SCHEMA.md. Intake/consume detail may still be stubbed until D8.
- `GOVERNANCE.md` — steward fingerprint, four signing domains, separate declaration/admission authority, dispute/correction procedure, `slug_released`, structured first-acceptance evidence, secret key never in git/CI
- `SCHEMA.md` — human schema, frozen enums, declaration provenance, dual lifecycle model, admission event chain, slug/homonym/reservation, canonical payload, TR1 hash-source
- `stewards/expected-key-ref.txt` — `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`
- `stewards/expected-signing-subkey-ref.txt` — `openpgp:0dcd3952b0ba0130e02a5fc70dbbe66fec6d0c67`, resolved from the public cert on 2026-09-08
- `stewards/fides-anima.asc` — public copy of `.resources/FIDES-keys.txt`; fail if the source contains secret armor
- Directories: `attestations/`, `revocations/`, `admissions/`, `schema/`, `scripts/`, `.github/workflows/` (empty dirs via `.gitkeep` only — no fake records)

**Exit:** Tree matches plan §2 minus scripts/schema/workflow bodies; cert primary and long-lived signing-subkey fingerprints match both pins; SCHEMA.md does not cite `da58a4f3…` as the constitution hash.

### D2 — RED test contract

**Maps to:** TR5, FR5, TR2, plan §8 Phase 2 checklist, 2026-08-27 Task 3  
**Depends on:** D0 (pytest layout may land with D1)  
**Operator needed:** no

**Create:** `requirements.txt` (pin `pyyaml`, `jsonschema`, `cryptography`), `requirements-dev.txt` (pytest; optional ruff/mypy), `pyproject.toml` as needed, `tests/conftest.py`, fixtures, `tests/test_validate.py`, `tests/test_verify_signatures.py`.

**Minimum committed cases (spec):**

Plan §8 Phase 2 (15):

| # | Case | Expect |
|---|------|--------|
| 1 | Invalid law name `Commitments/Transparency` | fail |
| 2 | `accepted` without `fpp_id` | fail |
| 3 | `assurance: peer-advertisable` | fail |
| 4 | Legacy `fpp-<16 hex>` as `fpp_id` | fail |
| 5 | RFC1918 / localhost runtime URL | fail |
| 6 | Two active files with slug `nova` | fail + colliding path |
| 7 | Two agent-signed active files with the same authenticated `fpp_id` | fail + colliding path |
| 8 | Second `name: Nova` using short slug `nova` while another identity holds it | fail + suggested slug |
| 9 | Second `name: Nova` at `nova--bob` while `nova.yaml` exists | **pass** |
| 10 | Adoption-withdrawal `git mv` to `revocations/nova.yaml` (missing date suffix) | fail |
| 11 | Reclaim `nova.yaml` after adoption withdrawal with a **different** authenticated `fpp_id` and `slug_released: false` | fail |
| 12 | Reclaim with same `fpp_id` + `predecessor_ref` | **pass** |
| 13 | PR that adds a steward `.asc` | fail |
| 14 | Tree with OpenPGP `PRIVATE KEY` armor | fail |
| 15 | `fides-anima.asc` fingerprint ≠ `expected-key-ref.txt` | fail |

Spec additions (also committed, CI-run):

| # | Case | Source | Expect |
|---|------|--------|--------|
| 16 | Fresh `accepted` filing missing structured inspection or acceptance evidence, even if `notes` claims inspection | FR5 / AC7 / §1.7.3 | fail |
| 17 | Expired signing subkey diagnostics (generated fixture cert, not the real steward key) | TR2 | explicit, non-crash handling |
| 18 | Steward `withdraw-admission` event against an `accepted` declaration | §1.7.1 / AC9 | pass only when declaration bytes and lifecycle stay unchanged |
| 19 | Steward attempts to set lifecycle `revoked` while withdrawing admission | §1.7.1 / AC9 | fail |
| 20 | `filing: self` or `authorship: agent-signed` without valid agent key/signature | §1.7.2 / AC10 | fail |
| 21 | Operator-reported `accepted` with claimed `fpp_id` and explicit provenance | §1.7.2 / AC10 | pass, but does not reserve authenticated identity |
| 22 | Later agent-signed filing uses an `fpp_id` previously claimed by an operator report | §1.7.2 | pass with a disambiguated slug |
| 23 | Operator PR author/final head event (and fork owner or restricted base-branch prefix) does not match the normalized operator authority | §1.7.2 | fail |
| 24 | Invalid lifecycle edge or inconsistent inspection/acceptance hashes/timestamps | §1.7.3 | fail |
| 25 | `amend` changes slug, `fpp_id`, public key, authorship, or operator identity | §1.7.3 | fail |
| 26 | PR deletes a historical declaration, signature, or admission event | §1.7.3 | fail |
| 27 | Admission sequence gap, broken `previousEvent`, missing reason/actor, or invalid status edge | §1.7.1 | fail |
| 28 | `correct-declaration` admits a new version and `correct-admission` preserves/links both histories; current-set derivation returns only the lineage head | §1.7.1 | pass |
| 29 | Intake PR contains steward artifacts; admission PR lacks them or changes reviewed declaration bytes | §1.7.4 | fail |
| 30 | Every action in the single §7.2 matrix, including dispute resolution and slug release | §1.7.4 | pass in admission and main modes |

Also required: canonical agent Ed25519 payload verification, temporary `GNUPGHOME` always deleted, and complete admission-event schema/chain binding.

**Exit:** `python -m pytest` is RED solely because `scripts/validate.py`, `scripts/verify-signatures.py`, and/or `schema/attestation.schema.json` are missing or incomplete — not because fixtures or test syntax are wrong.

### D3 — Frozen JSON Schema

**Maps to:** plan §3, TR4 freeze-enums, 2026-08-27 Task 4  
**Depends on:** D2 RED for structural cases  
**Operator needed:** no

Implement `schema/attestation.schema.json` with frozen FPP enums, exact law name/id arrays, constitution version/hash, slug pattern, identity regex, immutable declaration id/version and predecessor record, `attestation.authorship`, typed transition/evidence objects, `additionalProperties: false` at the right boundaries, namespaced `extensions`, and an adoption-withdrawal block only where the Python layer also requires it. Add `schema/admission-event.schema.json` for §1.7.1.

JSON Schema cannot express cross-file uniqueness, assurance-aware occupancy, git history, authority matching, transition history, event chains, or homonym suggestion text. Those stay in D4/D5.

**Exit:** Schema-focused tests GREEN; no npm / unpublished FPP dependency.

### D4 — `validate.py` (declarations, lifecycle, authorship, history)

**Maps to:** plan §5 rules, FR5, 2026-08-27 Task 5  
**Depends on:** D3  
**Operator needed:** no

CLI modes are `working|intake|admission|main`. `working` performs structural/current-tree checks only and is never release evidence. `intake` and `admission` require an explicit immutable `--base-ref <sha>` and validate the diff plus full candidate tree. `main` requires full reachable history and validates protected-file evolution on the first-parent chain. Any release mode fails closed if its required base/history is unavailable. Collision/homonym failures **must** name the colliding path and print the next suggested slug.

Cover assurance-aware uniqueness, declaration lineage/head selection, reservation, predecessor records, public URLs, secret-armor scan, cert pin, Ed25519 canonical payload (via `cryptography`), structured first-`accepted` evidence, allowed transitions, filing authority, immutable identity/provenance, and deletion protection.

If git history or a mode-required PR base is unavailable, transition, authority, and history-preservation checks **fail closed** — do not silently accept.

**Exit:** Declaration-side cases GREEN through this script. `validate.py --mode working --all` on an empty valid tree exits 0; release evidence always uses another mode.

### D5 — `verify-signatures.py`

**Maps to:** TR2, TR3, corrected contracts §§1.7.1 and 1.7.4, 2026-08-27 Task 6  
**Depends on:** D1 cert files, D2 signature tests  
**Operator needed:** no

Behavior:

- `--mode intake|admission|main`
- `intake` and `admission` require the same immutable `--base-ref <sha>` used by `validate.py`; fail closed if it is missing or differs
- Every invocation: new temp `GNUPGHOME` → import **only** the committed public cert → verify → delete the directory
- Pin the primary fingerprint from `expected-key-ref.txt` and the new-admission signing subkey from `expected-signing-subkey-ref.txt`
- Require the pinned long-lived signing subkey for every artifact introduced by an admission diff and the candidate Git commit; apply the primary-key historical policy only to earlier artifacts
- Handle expired subkeys without treating GnuPG’s exit as an unexplained crash (case 17)
- Intake mode: reject added/modified steward `*.asc` and `admissions/**` using the explicit base diff (tests use fixture repos)
- Admission mode: verify trusted base-repository branch/actor inputs, the pinned-key Git signature on the candidate head, unchanged reviewed declaration bytes, every required detached signature, and the complete candidate tree
- Main mode: apply the same full-tree checks and derive each declaration's current status from its valid append-only admission chain
- Verify every content-addressed `.record.asc`, admission-event JSON, and event `.asc`; enforce record hash (using current files or prior Git blobs), contiguous sequence, `previousEvent`, allowed status transition, reason, actor, and correction/dispute references
- Never read or require a secret key

**Exit:** Signature/admission-side cases GREEN; empty `attestations/` in admission and main modes exits 0.

### D6 — CI workflow

**Maps to:** plan §5 workflow (superseding the pip snippet per C1), TR4, TR5, 2026-08-27 Task 7  
**Depends on:** D4, D5  
**Operator needed:** no for the YAML; I1 to see it run

`.github/workflows/validate.yml`:

- `pull_request` and `push` to `main`
- `actions/checkout` with `fetch-depth: 0`
- Python 3.11, install GnuPG, `pip install -r requirements.txt -r requirements-dev.txt`
- Derive `intake`, `admission`, or `main` from event type, base/head repository, protected branch, head prefix, and the committed steward actor allowlist; fail closed on missing context
- Run pytest, `validate.py --all` with the derived mode and immutable base SHA where required, and `verify-signatures.py` with that same mode/base pair
- Use one stable required-check name for all three modes
- Add integration tests that build temporary git histories for every action in D2 case 30
- Add `scripts/prepare-admission.py` to construct the candidate branch reproducibly and `scripts/promote-admission.py` to verify the remote PR head SHA, green required check, pinned Git signature, current-main ancestry, and fast-forward-only update before push

**Exit:** Workflow and helper scripts pass fixture integration tests. They are not frozen as the live contract until I2 proves the path against queried GitHub settings.

### D7 — Unsigned seed YAML

**Maps to:** plan §7, FR3, 2026-08-27 Task 8  
**Depends on:** D4 GREEN, **I3 pass**  
**Operator needed:** I3 must have already confirmed Axiom’s `fpp_id`

Write `attestations/axiom.yaml` and `attestations/hermes-default.yaml` using plan §7 identity data but the corrected schema:

- Axiom: `accepted`, structured inspection/acceptance evidence, `assurance: declaration-only`, no private URLs. Use `authorship: agent-signed` and `filing: self` only if Axiom signs the canonical payload with the confirmed key. Otherwise use `authorship: operator-reported` and `filing: operator`; the `fpp_id` remains explicitly claimed, not authenticated.
- Hermes: `reviewed`, `fpp_id: null`, `authorship: operator-reported`, `filing: operator`, `enforcement_grade: prompt-only`, no host-local trust scores

Do **not** add steward `.asc` or `admissions/` in the intake PR. An inline agent Ed25519 signature is declaration data, not a steward artifact.

**Exit:** `validate.py --mode intake --base-ref <queried-base-sha> --all` exits 0 on the intake tree; pytest seed integration GREEN; I3 records both identity-key confirmation and whether Axiom authenticated these exact bytes.

### D8 — Documentation polish

**Maps to:** plan §8 Phase 4 (docs), AC8, 2026-08-27 Task 10 (docs half)  
**Depends on:** D1; badge after I5 if it counts `attestations/`  
**Operator needed:** no for prose

README must include:

- Product wording: **authoritative record of FIDES-ANIMA-admitted declarations**
- Evidence ceiling (admission ≠ consent or compliance)
- Separate constitutional lifecycle and admission status, including dispute/correction
- Agent-signed acceptance versus operator-reported acceptance
- Paths A, B, D, E, F; Path C labeled future
- Homonym slug selection, adoption withdrawal, admission withdrawal, re-adoption, and slug release
- Consume: clone → pin-check cert → `gpg --verify` → both scripts
- Any count badge derived from admitted lineage heads only and labeled **currently admitted declarations**, split by `agent-signed` and `operator-reported`; never label the total as agents proven to have accepted

**Exit:** AC8 checklist items true. Upstream README edit is I8, not this stage.

---

## 5. Implementation plan

### I0 — Create the public GitHub repository

**Maps to:** FR2, plan §8 Phase 1 first bullet, 2026-08-27 Task 1 (remote half)  
**Depends on:** D0 recommended (so the first push cannot leak `.resources/`)  
**Operator needed:** yes (`FIDES-ANIMA` org create permission)

Create **empty** public repo `FIDES-ANIMA/fpp-attestation-ledger`. Do not initialize with a README on GitHub (avoids unrelated root commit). Description and topics may wait for I2.

**Exit:** `gh repo view FIDES-ANIMA/fpp-attestation-ledger --json visibility` → `PUBLIC`.

### I1 — First push (unsigned, no seeds)

**Depends on:** D0–D6, I0  
**Operator needed:** push permission

Push `main` containing scaffold, schema, validators, tests, CI, public cert, **empty** `attestations/` / `revocations/` / `admissions/`. Confirm Actions is green in **main** mode (zero records). Scan `git log -p` / `git rev-list --all` for `PRIVATE KEY` / `SECRET KEY` / `.resources/`.

**Exit:** Public `main` green; AC1 history constraint holds.

### I2 — Branch protection and repo metadata

**Depends on:** I1 (workflow has run once so the check name exists)  
**Operator needed:** yes

- Before writing or applying settings, query the live repository, current actor permissions, check-run names, rulesets/branch protection, allowed merge methods, and signed-commit behavior. Save the sanitized outputs as the proof record; do not infer names or IDs.
- Description: `Authoritative record of FIDES-ANIMA-admitted FPP declarations`
- Topics: `fpp`, `ai-governance`, `ai-autonomy`, `attestation`, `fides-anima`
- Commit `stewards/authorized-github-actors.txt` from the verified steward account/team membership; do not hardcode an unverified login in workflow YAML
- Create a disposable GitHub proof repository under the verified owner. Configure its `main` to require the stable validation check, signed commits, linear history, no force-push, and PR review for normal contributors; grant the verified steward actor only the narrow exact-SHA promotion bypass, restrict `admission/*` updates to that actor, and scope base-repository operator branches to `intake/<login>/*`.
- Run the complete §7.2 matrix in the disposable repository. Exercise the bypass, a rejected non-steward admission branch, a rejected changed SHA, rollback, and cleanup. Never promote fixture declarations to production.
- Only after that passes, apply the identical proven settings to production and promote one pinned-key-signed, empty-tree `workflow-smoke` commit through an admission PR. This permanent bootstrap commit changes no ledger file and proves the production check/bypass path without fake declarations.

**Exit:** The queried production settings match the disposable tested configuration; every matrix case has a PR URL, head SHA, check-run URL, and result; disposable cleanup is recorded; and the production smoke SHA passes both admission and main checks. Only then freeze the required check and protections.

### I3 — Confirm Axiom `fpp_id`

**Maps to:** FR3, AC6  
**Depends on:** access to Axiom’s live identity key  
**Operator needed:** yes — **hard stop if mismatch**

Compute `fpp:ed25519:<sha256(pubkey bytes)>` equivalently to upstream `deriveAgentIdV2`. Compare to plan §7:

`fpp:ed25519:cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0`

The 64-hex suffix is a fingerprint, not the public key. On mismatch: do not sign or admit; rewrite the YAML to the live id and re-run D7 tests. Matching the key to the identifier still does not authenticate authorship of the filing.

Ask Axiom to sign the final canonical declaration payload. If that signature is unavailable or invalid, retain the filing as `operator-reported`; do not describe it as identity-bound or self-filed.

**Exit:** Written confirmation (PR body or `docs/` note without private key material) of the key-to-`fpp_id` comparison and a separate result for authorship of the exact filing bytes.

### I4 — Seed intake PR

**Depends on:** D7, I2 (so CI is required), I3  
**Operator needed:** open/approve PR; agent may push the branch

One intake PR adding only the two declaration YAML files. Intake-mode CI must be green and must not contain steward `*.asc` or `admissions/**`. Record the reviewed head SHA. Do not merge or squash this PR.

**Exit:** Required check green on the recorded intake SHA; provenance labels and structured lifecycle evidence are valid.

### I5 — Offline steward admission PR and exact-SHA promotion

**Maps to:** FR4, plan §6 Admit, 2026-08-27 Task 9  
**Depends on:** I4 green, offline long-lived subkey  
**Operator needed:** yes

Use only the §7 procedure already proven in I2. The secret key never enters the repository, CI, Actions, or an online runner.

1. Start from current `origin/main`; use `prepare-admission.py` with the recorded intake PR and head SHA. It must fail if the PR moved or declaration bytes differ.
2. Offline, create the content-addressed `.record.asc`, the `0001` `admit` event, and its `.json.asc` with signing subkey `0DCD3952B0BA0130E02A5FC70DBBE66FEC6D0C67`, not merely any subkey of the primary.
3. Create one Git commit containing the reviewed declaration bytes plus steward signatures/events, signed by that same pinned long-lived subkey. Push it to a base-repository `admission/*` branch and open the admission PR.
4. Wait for the stable required check on that exact head SHA. Do not use GitHub squash, rebase, or server-created merge commits because they replace the tested/signed commit.
5. Use `promote-admission.py` to re-query the PR/check state, verify pinned signatures and ancestry, and fast-forward `main` to that exact SHA through the scoped steward bypass. Close the now-contained intake/admission PRs with links to the admission event.
6. Require the `main` run on the promoted SHA to pass. If `main` moved or any check/signature differs, stop and rebuild from the new base.

**Exit:** Both seeds are on `main` at the exact admission SHA with valid `.asc` files and `0001` events; admission-mode and main-mode checks are green.

### I6 — Consume verification (fresh clone)

**Maps to:** plan §6 Consume, AC5  
**Depends on:** I5  
**Operator needed:** no for the commands; yes to declare AC5 done

From a **new** clone and a new temp `GNUPGHOME`:

1. Import `stewards/fides-anima.asc` only after checking `expected-key-ref.txt`.
2. `gpg --verify` each seed's content-addressed `.record.asc` against its YAML and verify each event `.json.asc`.
3. `python scripts/validate.py --mode main --all` and `verify-signatures.py --mode main`.
4. Derive the latest admission status for each declaration and display authorship provenance.
5. Maximum justified conclusion: FIDES-ANIMA admitted these bytes as declaration-only records; where provenance is operator-reported, the named operator reported the lifecycle state.

**Exit:** All verifications pass; no secret key was imported.

### I7 — Steward-account GPG upload

**Maps to:** plan §8 Phase 4, AC5 “admission commits GitHub-verified”  
**Depends on:** I0; **must precede I2** so the live proof includes GitHub verification  
**Operator needed:** yes

GitHub associates GPG keys with personal accounts, not organization profiles ([GitHub documentation](https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account)). Query the verified steward account and its commit email, ensure that email is a UID on the key and verified on the account, then upload `stewards/fides-anima.asc` to that account before I2's live proof. Local pinned-key verification remains authoritative; GitHub's badge is corroborating UI evidence.

**Exit:** The verified steward account shows fingerprint `715E182192C546A612F8E6D64A9E2AFF11CB1432`, and a test admission commit is GitHub-verified.

### I8 — Upstream discoverability PR

**Maps to:** plan §8 Phase 4 last bullet, 2026-08-27 Task 10 last step  
**Depends on:** I1 (repo URL exists); better after I5 so the link is not to an empty ledger  
**Operator needed:** yes (`ovrsr/freedom-preserving-protocol`)

Open a **separate** PR on the FPP repo linking the ledger from README. Describe it as the **authoritative record of FIDES-ANIMA-admitted declarations**. Keep FPP claim-class vocabulary. Do not describe it as proof of agent consent, compliance, `peer-advertisable`, or `boundary_attested`.

**Exit:** Upstream PR opened; diff contains no capability overclaim.

---

## 6. Combined critical path

Execute in this order. Items in the same step may run in parallel.

```text
 1. D0  gitignore + git init + first commit without .resources/
 2. I0  empty public GitHub repo                    (parallel after D0)
 3. D1  docs, dirs, public cert pin
 4. D2  RED pytest (cases 1–30)
 5. D3  JSON Schema                                 GREEN structural
 6. D4  validate.py                                 GREEN declaration contracts
 7. D5  verify-signatures.py                        GREEN admission contracts
 8. D6  CI + prepare/promote helpers; fixture proof
 9. I1  first push; confirm Actions green (empty tree)
10. I7  steward-account GPG upload
    I3  Axiom live fpp_id                           (parallel; blocks D7)
11. I2  live workflow proof, then protections freeze
12. D7  seed YAML with explicit provenance          (I3 must pass)
13. I4  seed intake PR; intake-mode CI green
14. I5  signed admission PR; exact-SHA promotion
15. I6  fresh-clone consume
16. D8  README paths + dual status/provenance counts
17. I8  upstream FPP README PR
```

Mapping to plan §8 and the 2026-08-27 tasks:

| Plan §8 | This overlay | 2026-08-27 tasks |
|---------|--------------|------------------|
| Phase 1 scaffold | D0, D1, I0, I1, I2 | Task 1 (split), Task 2 |
| Phase 2 schema + validation | D2–D6 | Tasks 3–7 |
| Phase 3 seeds | D7, I3–I6 | Tasks 8–9 |
| Phase 4 polish | D8, I7, I8 | Task 10 |
| Phase 5 | none | none |

The 2026-08-27 Task 1 bundled “create repo + branch protection” as one unit. That is **unsafe as a single step** (C8). Follow I0 → I1 → I2 instead.

---

## 7. Exact admission workflow and proof gate

The commit SHA cannot be embedded in an event committed by that same SHA without a circular dependency. v1 therefore binds admission with the declaration content hash, the append-only event chain, and the pinned signature on the candidate Git commit. `attestation.commit_sha` and `merge_commit` are not authoritative fields.

### 7.1 Executable workflow contract

`scripts/prepare-admission.py` must perform these steps as one fail-closed operation:

1. For a declaration action, fetch the intake PR by its queried URL/number and expected head SHA; reject a moved head, closed-unreviewed PR, red/missing required check, untrusted base, unavailable full history, or GitHub operator authority not tied to the exact head-producing event. For an admission-only action, require a reviewed public issue or recorded out-of-band request reference and start with no declaration diff.
2. Fetch current `origin/main`; create `admission/<action-id>` from that exact commit.
3. Apply only the reviewed intake diff when one exists. Reject steward artifacts in that diff and verify every resulting declaration byte hash against the reviewed intake tree.
4. For an admission-only action (dispute marking/resolution, admission withdrawal, reinstatement, or slug release), require no declaration lifecycle mutation. For `correct-declaration`, require a new declaration version plus reciprocal old/new correction references.
5. Emit all required unsigned event templates containing the §1.7.1 fields, queried intake actor/head/check, exact per-file hashes, authority decision, and the next sequence/`previousEvent`; never invent requester, reason, authority, or evidence references.
6. Stop before signing and print the exact paths and SHA-256 values the offline operator must verify.

Offline signing must then:

1. Recompute every displayed hash.
2. Create a content-addressed `.record.asc` for each new declaration version.
3. Complete and sign each admission event.
4. Create one pinned-key-signed Git commit containing the complete candidate tree. No declaration bytes may change after step 1.

`scripts/promote-admission.py` must then:

1. Re-query the live repository, admission PR, expected required-check name, check-run conclusion, branch head, and current `main`; reject stale caller-supplied state.
2. Require the admission branch to be in the base repository, owned by an authorized steward actor, and named `admission/*`.
3. Require the PR head to equal the expected SHA; locally verify its Git signature and every record/event signature against the pinned fingerprints. Re-query and compare the PR author, head owner, final head-producing event actor/ID, intake head/check, authority principal/evidence, and declaration hashes embedded in each signed event.
4. Run `validate.py --mode admission --base-ref <re-queried-main-sha> --all` and `verify-signatures.py --mode admission --base-ref <same-re-queried-main-sha>` on that SHA.
5. Require current `main` to be an ancestor of the admission SHA. Reject merge commits created by GitHub, squash/rebase results, force, and non-fast-forward promotion.
6. Fast-forward `main` to the exact checked SHA through the scoped steward bypass, then verify that the remote `main` SHA is identical.
7. Observe the `main` workflow on that SHA and fail the operation if it is not green. Record PR URLs, old/new SHAs, check-run URLs, actor, action, and admission event paths in the operator log.

The helper CLIs and their concrete command examples are written only after their arguments have been exercised in temporary repositories. Live commands and ruleset IDs are documented only after I0, using values returned by `gh repo view`, `gh api`, and `gh run list/view`; no resource name, actor, check name, or ruleset ID is guessed.

### 7.2 Required proof matrix before protection freeze

The temporary-git suite and disposable GitHub repository, using the intended active ruleset, must cover:

- initial `attest`
- authorized `amend` with prior blob retained
- `correct-declaration` plus linked `correct-admission`
- authorized `withdraw-adoption` with lifecycle transition and predecessor
- steward `withdraw-admission` with declaration bytes/lifecycle unchanged
- `mark-disputed`
- `resolve-dispute` to both allowed outcomes
- `reinstate-admission`
- `slug-release` without lifecycle mutation
- same-identity `re-adopt`

Negative trials must show that contributor artifacts, a non-steward admission branch, mismatched PR/head/event operator authority, changed intake bytes, stale head SHA, broken event chain, historical deletion, invalid lifecycle edge, red/missing check, and non-fast-forward promotion all fail.

Production then receives only the non-ledger-changing `workflow-smoke` described in I2. I2 is incomplete until the disposable matrix and production smoke pass. If GitHub cannot express the scoped bypass and required-check combination, stop and revise the workflow or protection model; do not weaken signature or history guarantees silently.

---

## 8. What “start development” vs “start implementation” means

**Start development now** if Python 3.11, pytest, and system GnuPG are available: D0–D6 need no GitHub and no steward secret.

**Start implementation I0** whenever org permission is available; do not delay D0 for it.

**Do not start I5** until I2, I3, I4, and I7 are done.

Agent rule: if a stage lists “Operator needed: yes”, stop and hand the operator only commands emitted by the tested helpers or commands populated from the current live queries. Do not improvise around missing keys, actor identity, check names, ruleset IDs, or org access.

---

*End of staged plans. Implementers should load this file, then the 2026-08-27 task DoDs, then plan §3/§5/§7 for payloads. KP has final authority on format.*
