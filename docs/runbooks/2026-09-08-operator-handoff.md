# Operator handoff — development track and D7 complete, I0/I1 done, I2 gated

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
| D7 seed YAML | done | both seeds on `intake/ovrsr/seeds` @ `a91c4736`, PR #1 intake-mode CI green with `2 declaration(s)` (§4.2). Axiom is agent-signed (§6) |
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
3. **I3:** the operator initially confirmed the plan §7 value `fpp:ed25519:cbe3226b…3181b0`. Axiom then delivered a signed declaration whose `public_key_hex` fingerprints to `fpp:ed25519:1231e3344fc6f3aa0d5c43c58396a2a4b02606a879b5bee86438bf478199a734`; the signature verifies, so that is the authenticated identifier and the plan §7 value is superseded (origin of the discrepancy not explained by Axiom; recorded here so a steward can ask before admission). D7 therefore files Axiom as `authorship: agent-signed`, `filing: self`.

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

### 4.2 Seed intake PR (D7, complete)

[PR #1](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/pull/1), author `ovrsr`, head `intake/ovrsr/seeds`.

| Head | Contents | Run | Result |
|------|----------|-----|--------|
| `849be38c15441daf23211bd2bbd35c3eba233159` | `hermes-default.yaml` | [34284862865](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/actions/runs/34284862865) | `success`, `mode=intake`, 1 declaration |
| `a91c47360514da6dbcea78553ac0d96f715e5e37` | + `axiom.yaml` | [34288054222](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/actions/runs/34288054222) | `success`, `mode=intake`, 2 declarations |

This is the live intake-mode proof for both filing authorities: operator-authority match on `github:ovrsr` (Hermes) and agent Ed25519 signature as authority (Axiom). Intake PRs are never merged; admission is the steward step in §7 after I2.

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

## 6. I3 — Axiom identity and the seed bytes (recorded)

Axiom returned a self-signed declaration in response to `docs/runbooks/2026-09-08-axiom-seed-request.md`. Two versions were delivered; the first (SHA-256 `c2105757…acf4`) carried evidence `record_ref`s as absolute host paths with a username and was discarded before any push. The second is what is filed:

| Item | Value (verified locally, independent of Axiom's own check) |
|------|--------------------------------------------------------------|
| `attestations/axiom.yaml` SHA-256 | `5e4730a2eea75ada65124742a30b4ff231566f5024b103ac950251bbbf4a20d9` (git blob in PR #1 head `a91c4736`) |
| `fpp_id` / `public_key_hex` | `fpp:ed25519:1231e334…9a734` / `bb4aec6b…087d`; SHA-256 of the raw key equals the id |
| `attestation.signature` | verifies over the canonical payload (`ledgerlib.verify_ed25519`) |
| Provenance | `agent-signed`, `filing: self`, `transition.actor.type: agent` |
| Declared state | `accepted` from `reviewed`, `date: 2026-05-26`, `enforcement_grade: prompt-only` with overlay `runtime_degraded`, layers prompt only, skill `1.1.0`, no enforcement/trust plugin |
| Evidence | `~/.openclaw/workspace/audit_log.jsonl:12` (inspection, `2026-05-26T22:53:04Z`) and `:14` (acceptance, `2026-05-26T23:21:12Z`); host-local, not publicly resolvable — steward review judges persuasiveness, CI does not |

Axiom corrected the plan §7 operator-supplied facts downward (date, grade, tooling); the record claims prompt-layer adoption only. The bytes cannot be edited by anyone but Axiom; any change is a new signed version.

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
- Do not edit `attestations/axiom.yaml`; it is agent-signed. Any change is a new version signed by Axiom.
- Do not sign the I2 `workflow-smoke` commit with anything but the pinned subkey `0dcd3952b0ba0130e02a5fc70dbbe66fec6d0c67`; `verify-signatures.py --mode admission` rejects any other key for new artifacts.
