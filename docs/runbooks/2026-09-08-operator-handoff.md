# Operator handoff — development track complete, I0/I1 done, I2 and Axiom evidence gated

Date: 2026-09-08. Plan: [`docs/plans/2026-08-30-fpp-attestation-ledger-v1-staged.md`](../plans/2026-08-30-fpp-attestation-ledger-v1-staged.md).

Every value below marked **queried** was read from the live environment on this date with the command shown. Nothing else is asserted about GitHub. Values marked **placeholder** must be replaced with the output of the query next to them before the command is run.

## 1. State of the development track

| Stage | Status | Proof |
|-------|--------|-------|
| D0 ignore rules, first commit | done | `git log --all -- .resources` is empty; history scan for `PRIVATE KEY BLOCK` / `SECRET KEY BLOCK` returns nothing outside the test fixture fragments |
| D1 contract docs, pins, public cert, empty dirs | done | `stewards/expected-key-ref.txt` = `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`, `stewards/expected-signing-subkey-ref.txt` = `openpgp:0dcd3952b0ba0130e02a5fc70dbbe66fec6d0c67` |
| D2 RED pytest contract | done | 165 tests across `tests/test_validate.py`, `tests/test_verify_signatures.py`, `tests/test_workflow_integration.py` |
| D3 JSON Schemas | done | `schema/attestation.schema.json`, `schema/admission-event.schema.json` |
| D4 `scripts/validate.py` | done | 94 declaration-side cases green |
| D5 `scripts/verify-signatures.py` | done | 51 admission-side cases green, including expired-subkey policy and GNUPGHOME hygiene |
| D6 CI + helpers + fixture proof | done | `.github/workflows/validate.yml`, `scripts/ci-context.py`, `scripts/prepare-admission.py`, `scripts/sign-admission.py`, `scripts/promote-admission.py`; full §7.2 matrix and negative trials pass against a bare origin |
| D7 seed YAML | **half done** | `attestations/hermes-default.yaml` committed on `intake/ovrsr/seeds`, intake-mode CI green (§4.2). `attestations/axiom.yaml` drafted at `docs/runbooks/axiom.seed-draft.yaml` (untracked); blocked on five operator-supplied evidence fields (§6) |
| D8 README polish | done | check name `ledger-validation`, consume path, provenance-split counts, helper flow |

Local toolchain used: Python 3.12 venv (`.venv/`), GnuPG 2.4.9 (Gpg4win), `ruff`, `mypy`; all clean. CI pins Python 3.11 per the plan; the code uses nothing newer than 3.11.

Repository `main` at handoff: `ada6952 Make fixture subprocesses hermetic against the host's GITHUB_* environment` (all commits unsigned; the first pinned-subkey commit is the I2 `workflow-smoke`).

## 2. Live environment (queried 2026-09-08)

```bash
gh auth status                       # queried: account ovrsr, scopes gist, read:org, repo, workflow
gh api orgs/FIDES-ANIMA --jq .type   # queried: Organization
gh api orgs/FIDES-ANIMA/memberships/ovrsr --jq '.role + " " + .state'   # queried: admin active
gh api orgs/FIDES-ANIMA/members --jq '.[].login'                        # queried: ovrsr (sole member)
gh repo view FIDES-ANIMA/fpp-attestation-ledger --json visibility       # queried: does not exist
gh repo view FIDES-ANIMA/protocol-attestation-ledger \
  --json name,visibility,isEmpty,createdAt
# queried: {"name":"protocol-attestation-ledger","visibility":"PRIVATE","isEmpty":true,"createdAt":"2026-09-08T20:06:36Z"}
git remote -v
# queried: origin https://github.com/FIDES-ANIMA/protocol-attestation-ledger.git
```

### Decisions recorded 2026-09-08 (operator)

1. **Repository name:** keep `FIDES-ANIMA/protocol-attestation-ledger`. Re-queried after the decision: `gh repo view FIDES-ANIMA/protocol-attestation-ledger --json visibility,isEmpty` → `PUBLIC`, `isEmpty: true`. The contract files were renamed in one commit (`schema/*.json` `$id`, `README.md`, `SCHEMA.md`, `pyproject.toml`, helper help text, test fixtures). The plan and requirements documents keep their historical name; the staged plan's I0 exit criterion is read as applying to this repository.
2. **Steward actor allowlist:** `ovrsr` is the only authorized GitHub actor. `stewards/authorized-github-actors.txt` is committed with that single login; it matches the membership query in §2.
3. **I3:** Axiom's `fpp_id` `fpp:ed25519:cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0` (plan §7) is confirmed by the operator. No statement was made that Axiom signs the seed bytes, so D7 files Axiom as `authorship: operator-reported`, `filing: operator`; the `fpp_id` is claimed, not authenticated, until an agent-signed `correct-declaration` arrives.

## 3. I0 — repository

Resolved by decision 1 above. Exit criterion re-queried:

```bash
gh repo view FIDES-ANIMA/protocol-attestation-ledger --json visibility   # PUBLIC (2026-09-08)
git remote get-url origin                                                 # https://github.com/FIDES-ANIMA/protocol-attestation-ledger.git
```

## 4. I1 — first push (unsigned, no seeds)

Pre-push scan (run from this checkout; both must print nothing):

```bash
git rev-list --all | while read c; do
  git grep -l -E "PRIVATE KEY BLOCK|SECRET KEY BLOCK" "$c" -- . ':!tests/conftest.py' ':!scripts/ledgerlib.py'
done
git log --all --oneline -- .resources
```

Then:

```bash
git push -u origin main   # performed 2026-09-08; see §4.1 for the recorded result
gh run list --repo FIDES-ANIMA/protocol-attestation-ledger --branch main --limit 1     # repository fixed by decision 1
gh run view <run-id> --repo FIDES-ANIMA/protocol-attestation-ledger                    # placeholder: run-id from the line above; must be success
```

The first run is in `main` mode over an empty ledger; both validators exit 0 on zero records (tested: `test_main_mode_empty_tree_passes`).

### 4.1 Recorded result (2026-09-08)

| Item | Value (queried) |
|------|-----------------|
| Pre-push scans | secret pattern scan matched only this runbook's own command text and the inert fixture fragments in `tests/conftest.py`, `scripts/ledgerlib.py`; `.resources` history empty |
| First push | `58d3491` → run [34284107472](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/actions/runs/34284107472) **failed**: 2 of 165 tests. Cause: the runner's real `GITHUB_TRIGGERING_ACTOR=ovrsr` leaked into the `ci-context.py` fixture subprocesses. Not reproducible locally without that variable. |
| Fix | `ada6952` strips inherited `GITHUB_*` from `Ledger._run`; reproduced locally with `GITHUB_TRIGGERING_ACTOR=ovrsr` before the fix (2 failed) and after (4 passed) |
| I1 exit | run [34284458694](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/actions/runs/34284458694) on `ada6952`: `success`, `mode=main`, 165 passed |
| Check-run name | `gh api repos/FIDES-ANIMA/protocol-attestation-ledger/commits/ada6952a5da0c2bb650697a3012259b914b636a2/check-runs --jq '.check_runs[].name'` → `ledger-validation` |

### 4.2 Seed intake PR (D7, partial)

[PR #1](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/pull/1), draft, author `ovrsr`, head `intake/ovrsr/seeds` @ `849be38c15441daf23211bd2bbd35c3eba233159`. Run [34284862865](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/actions/runs/34284862865): `success`, `mode=intake`, `1 declaration(s)`. This is the first live intake-mode proof (operator-authority match on `github:ovrsr`, base-repository branch under `intake/ovrsr/`). Do not admit it before I2 completes and `attestations/axiom.yaml` is added.

## 5. I2 — allowlist, rulesets, disposable proof

### 5.1 Steward actor allowlist (blocks every admission-mode run until committed)

`stewards/authorized-github-actors.txt` does not exist in this repository; only the test fixtures create one. `ci-context.py`, `validate.py`, and `verify-signatures.py` all fail closed on `admission/*` branches until it exists. Populate it only from a live membership query:

```bash
gh api orgs/FIDES-ANIMA/members --jq '.[].login'      # queried today: ovrsr
```

Write one lowercase login per line, commit, push through the normal path. Never write the fixture login `steward-bot` into it.

### 5.2 Query before writing any protection

```bash
gh api repos/FIDES-ANIMA/protocol-attestation-ledger/rulesets
gh api repos/FIDES-ANIMA/protocol-attestation-ledger/branches/main/protection
gh api repos/FIDES-ANIMA/protocol-attestation-ledger/commits/<sha>/check-runs --jq '.check_runs[].name'   # must list ledger-validation
gh api repos/FIDES-ANIMA/protocol-attestation-ledger --jq '{allow_merge_commit,allow_squash_merge,allow_rebase_merge,web_commit_signoff_required}'
```

Queried 2026-09-08 after I1: `rulesets` → `[]` (none); `branches/main/protection` → HTTP 404 `Branch not protected`; repository → `allow_merge_commit: true, allow_squash_merge: true, allow_rebase_merge: true, web_commit_signoff_required: false`; check-runs on `ada6952` → `ledger-validation`. Protections are therefore entirely unset; I2 starts from zero.

Save the sanitized outputs under `docs/runbooks/` as the proof record. Required check name is `ledger-validation` (job name in `.github/workflows/validate.yml`); confirm it from the check-runs query, not from this file.

### 5.3 Disposable repository

Create a throwaway repo under `FIDES-ANIMA`, push this same `main`, apply the intended ruleset, then run the §7.2 matrix with the helpers. The offline fixture proof already covers the same sequence (`tests/test_workflow_integration.py::test_matrix_full_lineage_journey`); the disposable run proves GitHub's bypass/required-check behavior, which the fixtures cannot. Record every PR URL, head SHA, check-run URL, and result. Delete the repo afterwards and record the deletion.

### 5.4 Hardening to apply in the same pass

- Pin `actions/checkout` and `actions/setup-python` to commit SHAs (currently tag-pinned `@v4` / `@v5`); take the SHAs from `gh api repos/actions/checkout/git/ref/tags/<tag>`.
- Confirm `GITHUB_TRIGGERING_ACTOR` semantics on re-runs match the authority rule (re-runner ≠ operator fails closed by design).

## 6. I3 — Axiom identity confirmation (D7 gate) and remaining Axiom inputs

Recorded 2026-09-08: (a) `fpp_id` `fpp:ed25519:cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0` confirmed by the operator; (b) no agent signature over the seed bytes was offered, so the seed is `operator-reported` / `filing: operator`. An agent-signed `correct-declaration` (same `declaration_id`, `version: 2`) can authenticate the `fpp_id` later without editing version 1.

`attestations/axiom.yaml` is fully drafted at `docs/runbooks/axiom.seed-draft.yaml` (untracked, outside `attestations/` on purpose). With throwaway values in the five fields below it passes `validate.py --mode working --all`; with the placeholders it fails schema validation, so it cannot be admitted by accident. `SCHEMA.md` §3.2 requires these for any `reviewed → accepted` version 1 and they are operator facts that must not be invented:

| Field | What is needed |
|-------|----------------|
| `adoption.transition.occurred_at` | UTC instant the acceptance took effect on 2026-08-24 |
| `adoption.evidence.inspection.record_ref` | URI or path of the constitution inspection record (the `71bf60ad…` hash check) |
| `adoption.evidence.inspection.inspected_at` | UTC instant of that inspection, `≤ accepted_at` |
| `adoption.evidence.acceptance.record_ref` | URI or path of the acceptance / FPP handshake record |
| `adoption.evidence.acceptance.accepted_at` | UTC instant of acceptance, `≤ occurred_at` |

Then: `git checkout intake/ovrsr/seeds && mv docs/runbooks/axiom.seed-draft.yaml attestations/axiom.yaml`, fill the fields, `python scripts/validate.py --mode working --all`, commit, push; PR #1 re-runs in intake mode.

If no inspection/acceptance record exists to reference, the honest alternative is to file Axiom as `reviewed` with `transition.from: null` (no evidence required) and move to `accepted` by `amend` once records exist. That is a scope change from plan §7 and is the operator's call.

## 7. Steward admission procedure (helpers, as tested)

Online machine (no secret key):

```bash
python scripts/prepare-admission.py query-intake --repo FIDES-ANIMA/protocol-attestation-ledger --pr <n> --expected-head <sha> --out /tmp/review.json
git fetch origin main "refs/pull/<n>/head"
python scripts/prepare-admission.py build --action attest --action-id <id> \
  --main-ref "$(git rev-parse origin/main)" --intake-ref <sha> --review-json /tmp/review.json \
  --reason-code intake-reviewed --reason "<why>" \
  --request-source-type github-pr --request-ref <pr-url> --requested-by github:<author> \
  --authority-basis github-pr-author-match --authority-principal github:<author> \
  --manifest /tmp/manifest.json
```

Offline machine (steward `GNUPGHOME`, the only place a secret key is used):

```bash
python scripts/sign-admission.py --manifest /tmp/manifest.json      # recomputes hashes, signs, one signed commit
git push origin admission/<id>
```

Then open the PR, wait for `ledger-validation` to be green on that exact SHA, and:

```bash
python scripts/promote-admission.py --repo FIDES-ANIMA/protocol-attestation-ledger --pr <n> --expected-head <sha> --log /tmp/promote.json
```

`--dry-run` verifies without pushing. All `<placeholders>` come from `gh pr view` / `git rev-parse`, never from memory.

Known helper limits, disclosed in code comments: `prepare-admission.py` derives the head-producing PR event's action as `synchronize` from a `pull_request`-triggered run (GitHub's runs API does not expose the activity type); `promote-admission.py --pr-json` is for fixture proof and offline verification and skips main-workflow observation unless `--observe-main` is passed.

## 8. Do not do

- Do not push to any private repository as the ledger; `protocol-attestation-ledger` is confirmed PUBLIC.
- Do not commit `stewards/authorized-github-actors.txt` with any login not returned by the membership query.
- Do not copy anything from `.resources/` into the checkout; it is ignored and must stay untracked.
- Do not fill the Axiom evidence fields with anything but the operator's actual records; the placeholders are rejected by CI on purpose.
- Do not sign the I2 `workflow-smoke` commit with anything but the pinned subkey `0dcd3952b0ba0130e02a5fc70dbbe66fec6d0c67`; `verify-signatures.py --mode admission` rejects any other key for new artifacts.
