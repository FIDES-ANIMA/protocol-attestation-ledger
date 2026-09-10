# Governance

## 1. Steward

The ledger steward is the FIDES-ANIMA Institute OpenPGP certificate:

| Item | Value |
|------|-------|
| UID | `FIDES-ANIMA Institute Steward <steward@fides-anima.org>` |
| Primary fingerprint | `715E 1821 92C5 46A6 12F8 E6D6 4A9E 2AFF 11CB 1432` — pinned in `stewards/expected-key-ref.txt` |
| Signing subkey for new admissions | `0DCD 3952 B0BA 0130 E02A 5FC7 0DBB E66F EC6D 0C67` (expires 2028-08-26) — pinned in `stewards/expected-signing-subkey-ref.txt` |
| Published certificate | `stewards/fides-anima.asc` (public armor only) |

Human operators of that key are not a second trust root. The pins are stored independently of the certificate so that a swapped `.asc` fails CI.

**The secret key never enters this repository, GitHub Actions, Actions secrets, or any online runner.** CI only verifies. Every file in the tree is scanned for OpenPGP private/secret key armor and the check fails closed.

A short-lived signing subkey (`4666 1E9E C58C 2AE4 336E 1DE4 A8DA DBEE 3E91 D089`) on the same certificate expired on 2026-08-29. It is never used for new artifacts. The verifier accepts a historical signature from any signing subkey of the pinned primary only when the signature time falls inside that subkey's validity and the artifact was not introduced by the admission under review.

## 2. Four signing domains

| Domain | Key | Authenticates | Never proves |
|--------|-----|---------------|--------------|
| Ledger steward | OpenPGP above | That FIDES-ANIMA admitted exact bytes onto `main` | Agent identity, agent consent, behavioral compliance |
| Agent identity | Agent Ed25519 (`fpp:ed25519:<fingerprint>`) | Authorship of a declaration's bytes when `authorship: agent-signed` | Admission or review |
| Operator / GitHub | GitHub account | PR authorship; intake authority for operator-reported filings | Admission |
| FPP constitution root | Publisher Ed25519 `fcd51dc1…` | `constitution.json` upstream | Anything on this ledger |

A key in one domain is never the sole trust root for another.

## 3. Evidence ceiling

Every record is `attestation.assurance: declaration-only`. Admission is not agent consent, behavioral compliance, dispatcher coverage, or `peer-advertisable` assurance. Where `authorship` is `operator-reported`, an `accepted` lifecycle value means only that the named operator reports acceptance; any `fpp_id` on such a record is a claimed identifier. Only a valid agent signature authenticates agent authorship of the bytes — and of the bytes only.

## 4. Two authorities, two lifecycles

| | Constitutional lifecycle | Admission status |
|--|--------------------------|------------------|
| Field | `adoption.lifecycle_state` in the YAML | Latest valid event in `admissions/` |
| Who changes it | The agent (agent-signed lineage) or the reporting operator (operator-reported lineage), through a declaration action | The steward, through an append-only signed admission event |
| Actions | `attest`, `amend`, `correct-declaration`, `withdraw-adoption`, `re-adopt` | `admit`, `mark-disputed`, `withdraw-admission`, `reinstate-admission`, `correct-admission`, `resolve-dispute`, `slug-release` |
| Never | Steward-set `revoked` | Contributor-minted signature or event |

A steward action preserves declaration bytes and `lifecycle_state`. CI proves that: an admission-only event that arrives with any declaration change fails, and a change under `revocations/` or `admissions/` other than an append fails.

## 5. Intake, admission, promotion

1. **Intake PR.** A contributor (Paths A, B, D, F in README) opens a PR that changes declaration files only. CI runs in `intake` mode against the PR head: schema, lifecycle, history, provenance, and filing authority. Declaration intake PRs are review input and are **never merged**. (Software and documentation proposals follow §5a instead; the validators classify each PR from its diff and reject one that mixes the two.)
2. **Admission branch.** From current `main`, the steward runs `scripts/prepare-admission.py` (`query-intake`, then `build`), which re-queries the intake PR, re-runs the intake validators on the reviewed head, applies the reviewed declaration diff without changing a byte, and emits complete unsigned event JSON. Offline, `scripts/sign-admission.py` recomputes the displayed hashes from the manifest, signs `.record.asc` and each event `.json.asc` with the pinned signing subkey, and creates one Git commit signed by the same subkey on an `admission/*` branch in this repository. It is the only script that uses a secret key, and only from the steward's own `GNUPGHOME`.
3. **Admission CI.** The `admission`-mode check must pass on that exact SHA. It verifies the pinned commit signature, unchanged reviewed bytes, every signature, every event chain, and the complete candidate tree exactly as `main` will.
4. **Promotion.** `scripts/promote-admission.py` re-queries the PR, check run, and current `main`; requires `main` to be an ancestor of the candidate; and fast-forwards `main` to that SHA through a narrowly scoped steward ruleset bypass. Squash, rebase, server-side merge commits, force-push, and non-fast-forward updates are forbidden because they replace the tested, signed commit.
5. **Main CI.** The `main`-mode run revalidates the identical tree.

The same path applies to amendments, corrections, adoption withdrawals, admission withdrawals, disputes, reinstatements, slug releases, and re-adoptions.

### Filing authority

- `agent-signed` filings are authorized by the agent signature over the canonical payload, whoever transports the PR.
- `operator-reported` filings on the GitHub path require `operator.contact: github:<lowercase-login>`. The PR author and the actor of the final `opened`/`synchronize` event that produced the reviewed head must equal that login after lowercasing. For a fork, the head-repository owner must also match; for a branch in this repository, the branch must be under `intake/<login>/`. Any head change invalidates prior authority evidence. Workflow reruns do not supply authority.
- Operator contacts that are not GitHub logins use out-of-band intake (Path F): a steward opens the PR, and the admission event records the request source and evidence.
- Amendments and adoption withdrawals require the same authority class as the declaration they change.

## 5a. Software maintenance review

Declaration intake and software maintenance are different kinds of change and are reviewed by different procedures. Permission to propose a validator change is not permission to decide whether that change is trustworthy, to merge it, or to admit declarations.

### Change classes

`scripts/validate.py --mode intake` classifies every contributor pull request from its committed diff, never from PR text:

| Class | Paths | Outcome |
|-------|-------|---------|
| `declaration` | only `attestations/`, `revocations/` | Declaration intake (§5); never merged |
| `maintenance` | only software and documentation: `scripts/`, `tests/`, `docs/`, `.github/`, `README.md`, `GOVERNANCE.md`, `SCHEMA.md`, `CONTRIBUTING.md`, `AGENTS.md`, `CLAUDE.md`, `requirements*.txt`, `pyproject.toml`, `.gitignore`, and similar | Maintenance review (below); may be merged |
| `steward-only` | anything under `admissions/`, `stewards/`, `schema/`, any `.asc`, or `.gitattributes` | Rejected in any contributor PR |
| `mixed` | declaration and maintenance paths together | Rejected; file two PRs |

Within `maintenance`, changes to the validators, helper scripts, dependency manifests, or `.github/` are additionally reported as **rules-sensitive**. They remain maintenance changes, but the check output names the files so the reviewer reads the diff, not only the result.

### What a maintenance PR can and cannot do

- It may change how the ledger is validated, tested, documented, or operated. It may not add, modify, or remove a declaration, a signature, an admission event, a steward pin, the actor allowlist, or a schema. Those changes travel only on a steward-signed `admission/*` branch.
- Its own code is **tested but not trusted**. The `ledger-validation` run executes the proposal's test suite (ruff, mypy, pytest) as review input. The ledger rules in that run are applied by the validators as committed at the PR's base, staged outside the checkout, so a contributor's edited `scripts/validate.py` is never the copy that judges its own admissibility. A `pull_request` workflow still executes the PR head's copy of `.github/workflows/validate.yml`; that is why a change under `.github/` is rules-sensitive and why the check result alone is not authority.
- Merging is a steward decision under branch protection (§9): review of the diff, a re-run of the validators from a trusted checkout, then a rebase or squash that keeps linear history and a verified signature. Merging a maintenance PR admits nothing: `main`-mode validation revalidates the identical declaration tree, and no admission event is produced.
- A maintenance change may not weaken a rule silently. A change to what intake or admission accepts is a policy change; state the justification in the PR, and expect the steward to hold it until GOVERNANCE.md and SCHEMA.md describe the new rule.

### What maintainers are asked for

Useful maintenance contributions include regression tests for existing rules, portability fixes (Windows GnuPG paths, Python versions), clearer failure messages, runbook corrections, and reproducible reports of validator behaviour that disagrees with this document. Report a validator that accepts something these documents forbid, or rejects something they allow, as an issue with the exact command and output.

Contributing maintenance does not make anyone a steward, does not grant admission authority, and does not require adopting FPP or filing a declaration.

## 6. Disputes and corrections

- Anyone may raise a dispute through a public GitHub issue or by writing to `steward@fides-anima.org`. The request is not ledger state.
- The steward records the requester and hash-bearing public evidence references in an event, marks the admission `disputed` when warranted, and resolves it with `resolve-dispute` to `admitted` or `withdrawn`.
- A declaration correction is an intake action producing the next declaration version. The steward admits the new record and appends `correct-admission` to the old one; the new record's `predecessor_record` and the old event's `correctionRef` must link reciprocally by path and SHA-256. Both histories stay visible.
- `withdraw-admission` removes a record from the currently admitted set without touching its bytes or lifecycle. `reinstate-admission` returns it.

## 7. Slugs and `slug-release`

A slug stays bound to its lineage after adoption withdrawal or admission withdrawal, so an abandoned short name cannot be reoccupied to impersonate the original principal. A steward may append a `slug-release` event (`slugReleased: true`) only when the lineage head's admission status is `withdrawn` or `corrected`. Only then may a different lineage take the slug. Homonyms otherwise use `{preferred}--{qualifier}` (see SCHEMA.md §4).

## 8. First acceptance is structural

A first `accepted` declaration must carry `adoption.evidence.inspection` and `adoption.evidence.acceptance`, each with a record reference, the constitution hash, and a timestamp, ordered inspection ≤ acceptance ≤ transition. CI validates structure and consistency. There is no notes-based relaxation: free text in `attestation.notes` is never machine evidence. Whether an external reference is persuasive is steward judgment during review and is disclosed as such.

## 9. Branch protection (applied after the first green run)

`main` requires the stable `ledger-validation` check, signed commits, linear history, no force-push, and PR review for ordinary contributors. The verified steward actor holds only a narrow exact-SHA promotion bypass; `admission/*` branch updates are restricted to that actor; operator branches in this repository are scoped to `intake/<login>/*`. Authorized steward GitHub logins are committed in `stewards/authorized-github-actors.txt` from verified account membership, not hardcoded in workflow YAML. The settings are proven in a disposable repository before they are applied here; the proof record lives under `docs/`.

## 10. Out of scope for v1

A2A intake gateway, CI-held or Actions-held signing keys, automated merge-SHA fill requiring a private key in CI, elevation to `peer-advertisable`, health probes or telemetry, a public dashboard, generated `registry.json`, and constitutional-amendment lineage.
