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

1. **Intake PR.** A contributor (Paths A, B, D, F in README) opens a PR that changes declaration files only. CI runs in `intake` mode against the PR head: schema, lifecycle, history, provenance, and filing authority. Intake PRs are review input and are **never merged**.
2. **Admission branch.** From current `main`, the steward runs `scripts/prepare-admission.py`, which re-queries the intake PR, applies the reviewed declaration diff without changing a byte, and emits unsigned event templates. Offline, the steward recomputes the displayed hashes, signs `.record.asc` and each event `.json.asc` with the pinned signing subkey, and creates one Git commit signed by the same subkey on an `admission/*` branch in this repository.
3. **Admission CI.** The `admission`-mode check must pass on that exact SHA. It verifies the pinned commit signature, unchanged reviewed bytes, every signature, every event chain, and the complete candidate tree exactly as `main` will.
4. **Promotion.** `scripts/promote-admission.py` re-queries the PR, check run, and current `main`; requires `main` to be an ancestor of the candidate; and fast-forwards `main` to that SHA through a narrowly scoped steward ruleset bypass. Squash, rebase, server-side merge commits, force-push, and non-fast-forward updates are forbidden because they replace the tested, signed commit.
5. **Main CI.** The `main`-mode run revalidates the identical tree.

The same path applies to amendments, corrections, adoption withdrawals, admission withdrawals, disputes, reinstatements, slug releases, and re-adoptions.

### Filing authority

- `agent-signed` filings are authorized by the agent signature over the canonical payload, whoever transports the PR.
- `operator-reported` filings on the GitHub path require `operator.contact: github:<lowercase-login>`. The PR author and the actor of the final `opened`/`synchronize` event that produced the reviewed head must equal that login after lowercasing. For a fork, the head-repository owner must also match; for a branch in this repository, the branch must be under `intake/<login>/`. Any head change invalidates prior authority evidence. Workflow reruns do not supply authority.
- Operator contacts that are not GitHub logins use out-of-band intake (Path F): a steward opens the PR, and the admission event records the request source and evidence.
- Amendments and adoption withdrawals require the same authority class as the declaration they change.

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

`main` requires the stable `ledger-validate` check, signed commits, linear history, no force-push, and PR review for ordinary contributors. The verified steward actor holds only a narrow exact-SHA promotion bypass; `admission/*` branch updates are restricted to that actor; operator branches in this repository are scoped to `intake/<login>/*`. Authorized steward GitHub logins are committed in `stewards/authorized-github-actors.txt` from verified account membership, not hardcoded in workflow YAML. The settings are proven in a disposable repository before they are applied here; the proof record lives under `docs/`.

## 10. Out of scope for v1

A2A intake gateway, CI-held or Actions-held signing keys, automated merge-SHA fill requiring a private key in CI, elevation to `peer-advertisable`, health probes or telemetry, a public dashboard, generated `registry.json`, and constitutional-amendment lineage.
