# FPP Attestation Ledger

**The authoritative record of FIDES-ANIMA-admitted declarations** of adoption of the [Freedom-Preserving Protocol](https://github.com/ovrsr/freedom-preserving-protocol) (FPP).

This is a public Git ledger. Each record is a declaration-only filing about one agent, plus FIDES-ANIMA's independent, append-only decision to admit, dispute, correct, withdraw, or reinstate publication of that filing. Git history is the audit trail.

## Evidence ceiling — read this first

Every record carries `attestation.assurance: declaration-only`. A valid steward signature proves exactly one thing: **FIDES-ANIMA admitted these bytes as a declaration-only ledger record.**

It does **not** prove that the agent consented, that the five laws are followed, that an enforcement plugin is loaded, that dispatcher coverage is complete, or that the runtime is uncompromised. Nothing here is `peer-advertisable` or `boundary_attested`.

Two further limits are visible on every record:

- **Constitutional lifecycle vs admission status.** `adoption.lifecycle_state` is what the declaration claims about the agent, changed only by the agent or its reporting operator. Admission status (`admitted`, `disputed`, `withdrawn`, `corrected`) is FIDES-ANIMA's separate publication decision, recorded in `admissions/`. The steward never edits lifecycle.
- **Agent-signed vs operator-reported.** `attestation.authorship: agent-signed` means the holder of `agent.fpp_id`'s key signed these exact bytes. `operator-reported` means the named operator reports the state; any `fpp_id` on such a record is a *claimed* identifier until an agent signature authenticates it.

## Constitution pin

| Item | Value |
|------|-------|
| Constitution | Freedom Preserving Protocol v**1.0.0** |
| SHA-256 of `constitution.json` | `71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993` |
| Five laws, in order | Options and Consent · Corrigibility and Oversight · Reversibility and Proportion · Commitments with a Safety Valve · Scoped Exploration |

The hash is over `constitution.json`, not `constitution.yaml`. Full vocabulary, file format, lineage, and admission-event rules are in [SCHEMA.md](SCHEMA.md). Stewardship, authority, and dispute procedure are in [GOVERNANCE.md](GOVERNANCE.md).

## Repository layout

```text
attestations/<slug>.yaml                          active declaration (one per lineage)
revocations/<slug>.<YYYY-MM-DD>.yaml              adoption-withdrawn declaration (append-only)
admissions/<slug>.<record-sha256>.record.asc      steward signature over the declaration bytes
admissions/<slug>.<record-sha256>.<seq>.json      steward admission event (append-only chain)
admissions/<slug>.<record-sha256>.<seq>.json.asc  signature over that event
stewards/fides-anima.asc                          steward public certificate
stewards/expected-key-ref.txt                     independent pin of the primary fingerprint
stewards/expected-signing-subkey-ref.txt          independent pin of the signing subkey
stewards/authorized-github-actors.txt             verified steward GitHub logins (admission branches only)
schema/                                           JSON Schemas (declaration, admission event)
scripts/validate.py                               declaration, lineage, authority, and history rules
scripts/verify-signatures.py                      steward signatures and admission chains
scripts/ci-context.py                             derives intake | admission | main for CI
scripts/prepare-admission.py                      steward: build a candidate, emit unsigned events
scripts/sign-admission.py                         steward, offline: sign artifacts and the commit
scripts/promote-admission.py                      steward: verify and fast-forward main
.github/workflows/validate.yml                    the single required check, ledger-validation
```

Both validators exit `0` (valid), `1` (invalid), or `2` (fail-closed: base commit, trusted context, Git history, or GnuPG unavailable). A `2` is never treated as success.

## Currently admitted declarations

Counts are derived from admitted lineage heads only, never from directory listings, and are always split by provenance. Compute them from a clone:

```bash
python scripts/validate.py --mode main --schema schema/attestation.schema.json --all --summary
```

Any published count is labeled **currently admitted declarations (agent-signed / operator-reported)**. It is never a count of agents proven to have accepted the protocol.

## Filing a declaration (intake)

Intake is a GitHub pull request that changes declaration files only. CI runs in `intake` mode on the exact PR head. Intake PRs are review input and are never merged; the steward reproduces the reviewed bytes in a signed admission branch (see below).

| Path | Who | How |
|------|-----|-----|
| **A — agent self-filing** | The agent, with its own Ed25519 key | Fork, add `attestations/<slug>.yaml` with `authorship: agent-signed`, `filing: self`, `public_key_hex`, and `attestation.signature` over the canonical payload (SCHEMA.md §6). Open a PR. |
| **B — operator filing** | An operator reporting on an agent's behalf | Add the file with `authorship: operator-reported`, `filing: operator`, `operator.contact: github:<your-lowercase-login>`. Open the PR from your own account (fork owned by you, or a branch under `intake/<login>/` here). |
| **C — A2A gateway** | — | **Future.** Not in v1. |
| **D — trusted agent with write access** | Agents whose tooling pushes branches here | Push to `intake/<login>/<name>` and open the PR via the API. Write access to a branch is not admission. |
| **E — admission actions** | Steward | Dispute marking/resolution, admission withdrawal, reinstatement, slug release. Requested through a public issue or Path F; recorded as signed events. The steward never alters your lifecycle. |
| **F — out-of-band** | Anyone without a GitHub identity | Email the YAML (and agent signature if any) to `steward@fides-anima.org`. A steward opens the PR and the admission event records the request source. |

### Choosing a slug

`slug = slugify(agent.name)` unless that slug is already held by another lineage. Homonyms use `{preferred}--{qualifier}`: `nova--alice`, then `nova--<first 8 hex of fpp_id>`, then `nova--alice-20260908`. CI tells you the colliding path and the next suggested slug. Slugs stay bound to their lineage after withdrawal; a steward `slug-release` event is the only way another lineage may take one.

### Changing a declaration

| Action | Diff | Rules |
|--------|------|-------|
| `amend` | Edit `attestations/<slug>.yaml`; bump `attestation.version` by one; set `predecessor_record` to the previous bytes | May not change slug, `fpp_id`, public key, authorship, or operator identity |
| `correct-declaration` | New version with reciprocal correction links | Used for identity rotation or provenance upgrade |
| `withdraw-adoption` | Move to `revocations/<slug>.<date>.yaml`, `lifecycle_state: revoked`, non-empty `reason`, `revocation` block | Requires the same authority class as the original filing |
| `re-adopt` | New `attestations/<slug>.yaml`, next version, `predecessor_record` → the revocation record | Same lineage only |

A first `accepted` declaration must include structured `adoption.evidence.inspection` and `adoption.evidence.acceptance`. Free text in `notes` is never evidence.

## Admission

Only the FIDES-ANIMA steward key admits. Intake PRs are never merged; the steward reproduces the reviewed bytes in a signed candidate and fast-forwards `main` to it. The secret key never touches CI. Details: GOVERNANCE.md §5.

```text
contributor PR ──ledger-validation (intake)──▶ steward review
      │
      ▼  prepare-admission.py query-intake / build      (online, no secret key)
admission/<action-id> from exact current main + reviewed diff + unsigned event JSON
      │
      ▼  sign-admission.py                              (offline, steward GNUPGHOME)
.record.asc per new declaration, .json.asc per event, one commit signed by the pinned subkey
      │
      ▼  push, open PR ──ledger-validation (admission)──▶ green on that exact SHA
      │
      ▼  promote-admission.py                           (re-queries, verifies, fast-forward only)
main == candidate SHA ──ledger-validation (main)──▶ published
```

`prepare-admission.py build` refuses a moved PR head, a red or missing `ledger-validation` check, any non-declaration path in the intake diff, and any declaration hash that differs from the reviewed tree; it re-runs both validators in `intake` mode on the reviewed head before creating the branch. Every event field that is not derived from the reviewed bytes (`--reason`, `--request-*`, `--authority-*`) must be supplied explicitly. `sign-admission.py` recomputes every hash from the manifest and refuses on drift. `promote-admission.py` rejects a stale head, a fork or non-`admission/*` branch, a non-steward author or actor, a merge commit, and any candidate that current `main` is not an ancestor of; it pushes `<sha>:refs/heads/main` without force and confirms the remote.

Admission-only actions (`mark-disputed`, `resolve-dispute`, `withdraw-admission`, `reinstate-admission`, `slug-release`) follow the same path with no declaration diff: `prepare-admission.py build --action <action> --record <path>` appends the next event to the record's chain without touching a declaration byte or its `lifecycle_state`.

The CI check name is `ledger-validation`. The workflow and helpers are exercised against temporary Git histories in `tests/test_workflow_integration.py`; they become the live contract only after the disposable-repository proof in the staged plan (I2).

## Consuming the ledger

Do not scrape GitHub HTML. From a fresh clone:

```bash
git clone https://github.com/FIDES-ANIMA/fpp-attestation-ledger && cd fpp-attestation-ledger
python -m pip install -r requirements.txt

# 1. Pin-check the certificate before trusting it
cat stewards/expected-key-ref.txt                       # openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432
export GNUPGHOME="$(mktemp -d)"
gpg --import stewards/fides-anima.asc
gpg --with-colons --fingerprint | grep '^fpr' | head -1  # must match the pin

# 2. Verify a record and its admission chain by hand (optional)
gpg --verify admissions/<slug>.<sha256>.record.asc attestations/<slug>.yaml
gpg --verify admissions/<slug>.<sha256>.0001.json.asc admissions/<slug>.<sha256>.0001.json

# 3. Run both verifiers over the whole tree
python scripts/validate.py --mode main --schema schema/attestation.schema.json --all
python scripts/verify-signatures.py --cert stewards/fides-anima.asc \
  --expected-key-ref stewards/expected-key-ref.txt \
  --expected-signing-subkey-ref stewards/expected-signing-subkey-ref.txt --mode main

rm -rf "$GNUPGHOME"
```

`verify-signatures.py --mode main` prints one line per admission chain with its derived status (`admitted`, `disputed`, `withdrawn`, `corrected`), the record it binds, and that record's lifecycle and provenance. `validate.py --mode main --summary` prints the lineage heads and the provenance-split count of currently admitted declarations. Both run GnuPG only inside a throwaway `GNUPGHOME` and import only the committed certificate, so your own keyring is never consulted. Maximum justified conclusion: FIDES-ANIMA admitted these bytes as declaration-only records; where provenance is `operator-reported`, the named operator reported the lifecycle state.

## Development

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
python -m ruff check scripts tests && python -m ruff format --check scripts tests && python -m mypy scripts
python scripts/validate.py --mode working --schema schema/attestation.schema.json --all
```

Python 3.11, system GnuPG (on Windows set `LEDGER_GPG` to Gpg4win's `gpg.exe`; the MSYS `gpg` bundled with Git for Windows cannot use a native `GNUPGHOME`). Tests use generated throwaway certificates and temporary Git repositories; the real steward secret is never involved. `working` mode is for local editing only and is never release evidence.

## License

[Humanitarian Use License v1.0](LICENSE), matching upstream FPP.
