# I2 protection proof — disposable repository record

Date: 2026-09-08. Actor: `ovrsr` (sole FIDES-ANIMA member, org admin). Every value below is copied from live command output on that date; nothing is inferred.

## 1. Disposable repository

```bash
gh repo create FIDES-ANIMA/ledger-protection-proof-20260908 --private ...
git push proof main                     # ledger main 2e72f8b7a6c8bbf2e54de207d679c467a820f4fb, same bytes as production
gh api -X POST repos/FIDES-ANIMA/ledger-protection-proof-20260908/rulesets --input <file>
# -> HTTP 403 "Upgrade to GitHub Pro or make this repository public to enable this feature."
gh repo edit ... --visibility public --accept-visibility-change-consequences
# rulesets then created (two POSTs returned a transient "Repository has been locked" right after the flip; retried once)
```

Rulesets are unavailable on private repositories under the org's free plan. The production ledger is public, so this does not affect it, but any future disposable proof must also be public.

## 2. Protection model as tested (revised during the proof, see §4)

Four repository rulesets plus two repository settings. The split exists because bypass is per-ruleset, not per-rule: the steward's bypass must never reach history or signature rules.

| Ruleset | Refs | Rules | Bypass |
|---------|------|-------|--------|
| `ledger-main-history` | `refs/heads/main` | `deletion`, `non_fast_forward`, `required_linear_history`, `required_signatures` | **none** |
| `ledger-main-review-and-check` | `refs/heads/main` | `pull_request` (1 approving review, dismiss stale, allowed method `merge` only), `required_status_checks` (`ledger-validation`, strict) | `OrganizationAdmin`, `always` |
| `ledger-admission-branches-steward-only` | `refs/heads/admission/**` | `creation`, `update`, `deletion` | `OrganizationAdmin`, `always` |
| `ledger-admission-branches-signed` | `refs/heads/admission/**` | `required_signatures`, `non_fast_forward` | **none** |

Repository settings: `allow_squash_merge: false`, `allow_rebase_merge: false`, `allow_merge_commit: true` (merge commits are then blocked for everyone by the unbypassable `required_linear_history`).

Net effect: `main` advances only by a fast-forward push whose commits carry GitHub-verified signatures, made by an org admin. No GitHub-created merge, squash, or rebase commit can land, with or without `--admin`. `admission/**` can be created or updated only by an org admin and only with verified-signed commits. The exact JSON bodies are in `docs/runbooks/rulesets/`.

What GitHub cannot express, enforced by the validators and `promote-admission.py` instead: "exact-SHA" scoping of the bypass (the steward's push is subject to history and signature rules but not to the check; the helper re-queries the check on the exact SHA before pushing), per-login scoping of `intake/<login>/*` (validators), and the steward actor allowlist (`stewards/authorized-github-actors.txt`; GitHub's `OrganizationAdmin` role is the closest available actor type and today has one member).

## 3. Trials (all as `ovrsr`, i.e. the bypass actor)

| # | Trial | Command | Result (verbatim from `remote:` / `gh`) |
|---|-------|---------|------------------------------------------|
| T1 | Unsigned fast-forward push to `main` | `git commit --allow-empty && git push origin main` | `GH013 ... - Commits must have verified signatures. Found 1 violation: dca4183231624789d6e68e9af7768d77813300cb` — rejected; the review/check rule was bypassed, the signature rule was not |
| T2 | Force-push `main` | `git push --force origin main` | `- Cannot force-push to this branch` and `- Commits must have verified signatures.` — rejected |
| T3 | Delete `main` | `git push origin --delete main` | `refusing to delete the current branch` — rejected |
| T4 | Unsigned commit to `admission/t4` | `git push origin admission/t4` | `GH013 ... - Commits must have verified signatures.` — rejected (creation was bypassed by the admin role; the signature ruleset has no bypass) |
| T5a | Intake PR #1 from `intake/ovrsr/t5` (adds `attestations/.t5-probe`); `ledger-validation` | run `34289415478` | `mode=intake`; `FAIL attestations/.t5-probe: only <slug>.yaml declarations may live under attestations/ and revocations/` — the check went red as intended |
| T5b | `gh pr merge 1 --merge` / `--squash` / `--rebase` (no `--admin`) | | all three: `the base branch policy prohibits the merge` |
| T5c | `gh pr merge 1 --merge --admin` | | `Merge commits are not allowed on this repository.` (linear history, unbypassable) |
| **T5d** | `gh pr merge 1 --squash --admin` | | **merged.** `main` moved `2e72f8b7 → 6bdd0f8a025e7a6e9474e2fb6429528c031e8b1c` with a red check. Cause: the squash commit is created and signed by GitHub's web-flow key, so it satisfies `required_signatures` and linear history, while the admin bypass on the review/check ruleset waived both the check and `allowed_merge_methods`. |
| T6 | After `gh repo edit --enable-squash-merge=false --enable-rebase-merge=false`: new intake PR #2, `--admin` with each method | | `Merge commits are not allowed`, `Squash merges are not allowed`, `Rebase merges are not allowed`; `main` unchanged at `6bdd0f8a` |

T5d is the finding this proof existed to surface. The plan (§7.2) says to revise the protection model rather than weaken guarantees; the revision is the two repository merge settings in §2, verified by T6. The improperly landed squash commit remains on the disposable `main` because rollback would itself need a verified-signed forward commit (no steward key on this machine); its `main`-mode run `34289629114` reached `mode=main` and was cancelled by the archive step below. The same tree had already failed the intake check on the same file.

Not exercisable with a single GitHub account: a non-steward pushing to `admission/**`, a non-steward opening an admission PR, the positive bypass (verified-signed FF push by the steward). The negative actor cases are covered by fixtures (`test_case29e`, `test_case29f`, `test_ci_context_admission_requires_allowlisted_steward`); the positive path is the production `workflow-smoke` in the handoff §5.5 and requires I7 first.

## 4. Cleanup

```bash
gh pr close 2 --delete-branch; git push origin --delete intake/ovrsr/t5
gh repo archive FIDES-ANIMA/ledger-protection-proof-20260908 -y
# -> {"isArchived":true,"visibility":"PUBLIC"}
gh repo delete FIDES-ANIMA/ledger-protection-proof-20260908 --yes
# -> HTTP 403: needs the "delete_repo" scope
```

Archived, not deleted. Operator: `gh auth refresh -h github.com -s delete_repo && gh repo delete FIDES-ANIMA/ledger-protection-proof-20260908 --yes`, then record the deletion here.
