# Operator handoff — D0–D8 and I0–I8 done, I2 frozen, seeds admitted, upstream PR opened

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

Repository `main` at the original handoff: `ada6952 Make fixture subprocesses hermetic against the host's GITHUB_* environment` (all commits unsigned; the first pinned-subkey commit is the I2 `workflow-smoke`). At the end of this runbook `main` is `72d95bc attest: seeds-2026-09` (§5.6), and every commit after `ada6952` is pinned-subkey signed and GitHub-verified.

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
3. **I3:** the operator initially confirmed the plan §7 value `fpp:ed25519:cbe3226b…3181b0`. Axiom then delivered a signed declaration whose `public_key_hex` fingerprints to `fpp:ed25519:1231e3344fc6f3aa0d5c43c58396a2a4b02606a879b5bee86438bf478199a734`; the signature verifies, so that is the authenticated identifier and the plan §7 value is superseded (the operator subsequently confirmed that the plan §7 value was an operator error and that Axiom's state was validated; I3 is closed). D7 therefore files Axiom as `authorship: agent-signed`, `filing: self`.

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

## 5. I2 — allowlist, rulesets, disposable proof, production protections

### 5.1 Steward actor allowlist — done

`stewards/authorized-github-actors.txt` = `ovrsr`, from `gh api orgs/FIDES-ANIMA/members --jq '.[].login'` (2026-09-08). Never write the fixture login `steward-bot` into it.

### 5.2 Baseline queried before any protection (2026-09-08, after I1)

`rulesets` → `[]`; `branches/main/protection` → HTTP 404 `Branch not protected`; repository → `allow_merge_commit: true, allow_squash_merge: true, allow_rebase_merge: true, web_commit_signoff_required: false`; check-runs on `ada6952` → `ledger-validation`. Description and topics set and queried back: `Authoritative record of FIDES-ANIMA-admitted FPP declarations`; `fpp, ai-governance, ai-autonomy, attestation, fides-anima`.

### 5.3 Disposable proof — done, with one model revision

Full record: [`2026-09-08-i2-protection-proof.md`](2026-09-08-i2-protection-proof.md). Ruleset bodies: [`rulesets/`](rulesets/). Summary:

- Four rulesets: `ledger-main-history` (deletion, non-FF, linear history, verified signatures; **no bypass**), `ledger-main-review-and-check` (PR review + required check `ledger-validation`; bypass `OrganizationAdmin` always), `ledger-admission-branches-steward-only` (create/update/delete `admission/**`; bypass `OrganizationAdmin`), `ledger-admission-branches-signed` (verified signatures, non-FF on `admission/**`; **no bypass**).
- Trials T1–T4 and T5b/T5c rejected as intended, including for the org admin.
- **T5d finding:** `gh pr merge --squash --admin` landed a GitHub-signed squash commit on `main` with a red check. Revision: repository settings `allow_squash_merge: false`, `allow_rebase_merge: false` (merge commits stay enabled but are blocked by the unbypassable linear-history rule). T6 confirmed all three `--admin` merge methods are refused afterwards.
- Rulesets require a **public** repository on the org's plan.
- Disposable repo is archived, not deleted (`delete_repo` scope missing): operator runs `gh auth refresh -h github.com -s delete_repo && gh repo delete FIDES-ANIMA/ledger-protection-proof-20260908 --yes` and records it in the proof file.

Resulting invariant: `main` and `admission/**` advance only through fast-forward pushes of commits with **GitHub-verified** signatures by an org admin. The check on the exact SHA is enforced by `promote-admission.py`'s re-query (GitHub cannot scope a bypass to a SHA); the steward allowlist and `intake/<login>/*` scoping are enforced by the validators.

### 5.4 Production application

The same four ruleset bodies and the two merge settings were applied to `FIDES-ANIMA/protocol-attestation-ledger` immediately after this runbook was pushed. From that moment the history ruleset blocks every unsigned push, including runbook edits; `main` changes only by steward-signed commits. Verify at any time:

```bash
gh api repos/FIDES-ANIMA/protocol-attestation-ledger/rulesets --jq '.[] | {id,name,enforcement}'
gh api repos/FIDES-ANIMA/protocol-attestation-ledger --jq '{allow_merge_commit,allow_squash_merge,allow_rebase_merge}'
# expected: 4 active rulesets named as in §5.3; {true,false,false}
```

Hardening still open: pin `actions/checkout` / `actions/setup-python` to commit SHAs (`gh api repos/actions/checkout/git/ref/tags/<tag>`); a workflow edit, therefore now a steward-signed commit.

### 5.5 I7 and `workflow-smoke` — done (2026-09-08)

Correction to the earlier text: the steward secret key **is** on the operator's machine, in the Gpg4win keyring under `%APPDATA%\gnupg` (binary `C:\Program Files\GnuPG\bin\gpg.exe`, GnuPG 2.5.18). The earlier "no secret key" statement came from probing a wrong path. The secret key is still never copied anywhere else; only `git commit -S` and `sign-admission.py` touch it, through gpg-agent.

| Item | Value (queried / observed) |
|------|----------------------------|
| I7 scopes | `gh auth status` → `admin:gpg_key, gist, read:org, repo, user, workflow` |
| I7 key on `ovrsr` | `gh api user/gpg_keys` → `key_id 4A9E2AFF11CB1432`, `steward@fides-anima.org` `verified: true` |
| Smoke commit | `68389cdb7785625aa1793a9973ce295b3e93bbf7`, empty, author/committer `FIDES-ANIMA Institute Steward <steward@fides-anima.org>`; `git verify-commit --raw` → `VALIDSIG 0DCD3952B0BA0130E02A5FC70DBBE66FEC6D0C67 … 715E182192C546A612F8E6D64A9E2AFF11CB1432` |
| GitHub verification | `commits/68389cd… .commit.verification` → `verified: true, reason: valid` (the ruleset accepted the push) |
| Admission PR | [PR #2](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/pull/2), branch `admission/workflow-smoke` |
| Admission-mode run | [34292591813](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/actions/runs/34292591813) `success`, `mode=admission`, `0 declaration(s)` |
| Promotion | `promote-admission.py --pr 2 --expected-head 68389cd…` dry run then real: `main fast-forwarded 73541820b26d -> 68389cdb7785 and confirmed on the remote` |
| Main-mode run | [34292804068](https://github.com/FIDES-ANIMA/protocol-attestation-ledger/actions/runs/34292804068) `success`, `event: push`, `mode=main` |

**I2 is frozen** at `main = 68389cdb7785625aa1793a9973ce295b3e93bbf7`.

Two operational notes from the run. First, the pinentry prompt timed out once (60 s) and rejected one mistyped passphrase before succeeding; nothing was committed on the failed attempts. Second, a helper defect: `promote-admission.py` recorded `main_check_run` pointing at the **PR** run `34292591813` rather than the push-triggered `main` run, because it matched check-runs by SHA and both runs share the SHA. It reported "green" after 6 s while the real `main` run was still in progress (it later passed). Fixed in the commit that carries this runbook update: the observe step now queries `actions/runs?branch=main&event=push&head_sha=<sha>` and waits for that run specifically (`test_observe_main_waits_for_the_push_run_not_the_pr_run`, `test_observe_main_rejects_a_failed_push_run`). That fix itself went to `main` through an `admission/*` branch with a signed commit and was promoted with the fixed helper, which is the live test of the fix.

### 5.6 I5 — admit the seeds — done (2026-09-08, UTC 2026-09-09)

Intake PR **#1**, head **`a91c47360514da6dbcea78553ac0d96f715e5e37`**, author `ovrsr`, check `ledger-validation` success (run 34288054222). The commands below were run as written, with one deviation recorded in 5.6.1.

| Step | Queried result |
|------|----------------|
| `query-intake` + `build` | `~/review-seeds.json`, `~/manifest-seeds.json`; branch `admission/seeds-2026-09` off `origin/main` `0cd4e491` |
| `sign-admission.py` | 2 `.record.asc` + 2 `0001.json` + 2 `.json.asc`, all `VALIDSIG 0DCD3952B0BA0130E02A5FC70DBBE66FEC6D0C67`; events `occurredAt 2026-09-09T00:23:57Z`, `reasonCode intake-reviewed`, `review.headSha a91c4736`; authority Hermes `github-pr-author-match`/`github:ovrsr`, Axiom `agent-signature`/`fpp:ed25519:1231e334…9a734` |
| Signed commit | `72d95bcfb1e9da0eeeaa101ed4617646b530df21` `attest: seeds-2026-09`, `FIDES-ANIMA Steward <steward@fides-anima.org>`, `git log %G?` = `G`; GitHub `verification.verified=true reason=valid` |
| Local pre-push check | `ci-context.py` on a synthesized `pull_request` payload → `mode=admission`; `validate.py` and `verify-signatures.py --mode admission --base-ref 0cd4e491` both OK |
| Push + PR | ruleset accepted the push to `admission/seeds-2026-09`; PR **#4**; `ledger-validation` run 34295404078 success on the exact SHA, log shows `mode=admission`, `2 declaration(s), 2 admission chain(s)`; `mergeStateStatus=BLOCKED` (expected: merges are disabled) |
| Promotion | `promote-admission.py --pr 4 --expected-head 72d95bc… --intake-review-json ~/review-seeds.json` dry run then real: `main fast-forwarded 0cd4e491e59d -> 72d95bcfb1e9 and confirmed on the remote`; observer waited for the **push** run 34295611314 (distinct from the PR run), log shows `OK mode=main: 2 declaration(s), 2 admission chain(s)` |
| Housekeeping | GitHub marked PR #4 `MERGED` (fast-forward to its head); PR #1 closed unmerged with a comment linking both `0001.json` events at `72d95bc` |

#### 5.6.1 Deviation: the commit had to be redone by hand

`sign-admission.py` produced and staged all six artifacts but the operator's commit attempt failed twice with `gpg: skipped "0dcd…0c67!": No secret key` (once from PowerShell, once from Git Bash). Two causes, both host-local:

1. `gpg.program` is unset in this checkout, so `git commit -S` called Git for Windows' bundled `/usr/bin/gpg`, whose keyring (`~/.gnupg`) holds no secret key. The steward key lives in the Gpg4win keyring (`C:/Program Files/GnuPG/bin/gpg.exe`).
2. The checkout's `user.email` is `contact@fides-anima.org`. GitHub verifies a signature only when the committer email is both a UID on the key and verified on the account; that is `steward@fides-anima.org` (the address the I7 upload was verified against). A commit with `contact@` would sign locally and then be rejected by the `admission/**` ruleset as unverified.

The staged tree was inspected before committing (all four `.asc` verify against the pin from an ephemeral home; declaration SHA-256s equal the manifest; events carry per-record authority), then committed with per-command overrides and no change to the repo config:

```bash
git -c "gpg.program=C:/Program Files/GnuPG/bin/gpg.exe" -c "user.signingkey=0DCD3952B0BA0130E02A5FC70DBBE66FEC6D0C67!" \
    -c "user.name=FIDES-ANIMA Steward" -c "user.email=steward@fides-anima.org" commit -S -m "attest: seeds-2026-09"
```

Note that `sign-admission.py` itself sets `gpg.program` and `user.signingkey` for its own commit (and would have avoided cause 1), but not the author/committer identity; it inherits `user.email` from the checkout. Before the next admission on this machine either set `user.email=steward@fides-anima.org` and `gpg.program` in the checkout's local config, or run `sign-admission.py` with `GIT_AUTHOR_EMAIL`/`GIT_COMMITTER_EMAIL` exported. PowerShell also does not accept `&&` in this Windows PowerShell version; run the commands from Git Bash.

### 5.7 I6 — fresh-clone consume — done (2026-09-08)

From a new clone of `main` at `72d95bc` into a temp directory and a new empty `GNUPGHOME` (native `gpg.exe` needs a Windows-style path; an MSYS `/tmp/...` path is not usable):

1. `stewards/expected-key-ref.txt` = `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`; `gpg --import-options show-only` on `stewards/fides-anima.asc` reports primary fingerprint `715E182192C546A612F8E6D64A9E2AFF11CB1432` — match, then imported. `--list-secret-keys` in that home: none.
2. `gpg --verify` of both `.record.asc` against their YAML and both `0001.json.asc` against their JSON: four `VALIDSIG 0DCD3952B0BA0130E02A5FC70DBBE66FEC6D0C67`. `sha256sum` of the two YAMLs equals the content addresses in the file names.
3. `validate.py --mode main --all --summary` and `verify-signatures.py --mode main`: both OK.
4. Derived status (from the `--summary` output): `axiom.yaml` lineage `98e0df7c…` v1, lifecycle `accepted`, **agent-signed**, admission `admitted`; `hermes-default.yaml` lineage `60f012f5…` v1, lifecycle `reviewed`, **operator-reported**, admission `admitted`. `currently admitted declarations: 2 (agent-signed: 1, operator-reported: 1)`.
5. Maximum justified conclusion, as printed by the tools: FIDES-ANIMA admitted these bytes as declaration-only records; for `hermes-default`, `github:ovrsr` reported the lifecycle state; for `axiom`, the agent's own Ed25519 signature over the canonical payload authenticates authorship. Neither proves consent or behavioral conformance.

AC5 is met on the evidence above; the operator declares it done. The temp clone and `GNUPGHOME` were deleted afterwards.

### 5.8 I8 — upstream discoverability PR — opened (2026-09-08)

The FPP repository is `FIDES-ANIMA/protocol` (queried from the local checkout's `origin`; the plan's `ovrsr/freedom-preserving-protocol` is stale). `MASTER_CONTEXT.md` there already listed the ledger as optional install step 8 but `README.md` did not link it. Opened [FIDES-ANIMA/protocol#1](https://github.com/FIDES-ANIMA/protocol/pull/1) from branch `docs/link-attestation-ledger` (commit `2d06eaa`, README only, 6 insertions): a `### Declare (optional)` subsection under Install naming the ledger the **authoritative record of FIDES-ANIMA-admitted adoption declarations**, claim class **declaration-only**, stating what an admitted record does and does not prove. The words `consent`, `compliance`, `peer-advertisable`, `boundary_attested` occur in the diff only in negated form (checked with `gh pr diff | rg`). The FPP repo's own conventions were followed (unsigned commit as `Steward <contact@fides-anima.org>`, no rulesets). Merge is the operator's call; the exit criterion "upstream PR opened; diff contains no capability overclaim" is met.

### 5.9 Local config change on this machine (2026-09-08)

Per §5.6.1, the ledger checkout's local git config now has `gpg.program=C:/Program Files/GnuPG/bin/gpg.exe` and `user.email=steward@fides-anima.org` (`user.name` left as `ovrsr`; the name does not affect GitHub verification). `sign-admission.py` will therefore commit without the manual step. This is host-local state, not repository content.

All plan stages D0–D8 and I0–I8 are now done or, for I8, opened and awaiting the operator's merge.

#### Commands as run for I5 (kept for the next admission)

```bash
python scripts/prepare-admission.py query-intake --repo FIDES-ANIMA/protocol-attestation-ledger --pr 1 \
  --expected-head a91c47360514da6dbcea78553ac0d96f715e5e37 --out ~/review-seeds.json
git fetch origin main refs/pull/1/head
python scripts/prepare-admission.py build --action attest --action-id seeds-2026-09 \
  --main-ref "$(git rev-parse origin/main)" --intake-ref a91c47360514da6dbcea78553ac0d96f715e5e37 \
  --review-json ~/review-seeds.json --reason-code intake-reviewed \
  --reason "Steward reviewed PR #1: hermes-default operator-reported reviewed; axiom agent-signed accepted." \
  --request-source-type github-pr --request-ref https://github.com/FIDES-ANIMA/protocol-attestation-ledger/pull/1 \
  --requested-by github:ovrsr --authority-basis github-pr-author-match --authority-principal github:ovrsr \
  --manifest ~/manifest-seeds.json
```

The `--authority-*` values describe the operator-reported record (Hermes). The helper assigns `agent-signature` / Axiom's `fpp_id` to Axiom's event itself, because `verify-signatures.py` requires that for an agent-signed record (`test_mixed_provenance_intake_gets_per_record_authority`; a mixed PR could not be admitted in one candidate before this fix). Then, with the steward keyring (`--gpg "C:/Program Files/GnuPG/bin/gpg.exe"` on this machine): `sign-admission.py --manifest ~/manifest-seeds.json`, push `admission/seeds-2026-09`, open the PR, wait for green on the exact SHA, `promote-admission.py --pr <n> --expected-head <sha> --intake-review-json ~/review-seeds.json`. Close PR #1 with a link to the two `0001` events. Outcome: §5.6 table; the manual-commit deviation: §5.6.1.

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
