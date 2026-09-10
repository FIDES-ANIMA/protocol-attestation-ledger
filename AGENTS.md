# Working on the FPP attestation ledger

This file guides authorized development in this repository. It does not ask a
reader to adopt FPP, file a declaration, act as a steward, or leave an unrelated
task. Human and agent contributions to the software are welcome; filing a
declaration is a separate action with its own procedure.

## Orientation

Read `README.md` first, especially *Evidence ceiling*. Every record here is
declaration-only: a steward signature proves that FIDES-ANIMA admitted specific
bytes, nothing about agent consent, behaviour, or runtime integrity. Do not write
documentation, messages, or tests that imply otherwise.

`GOVERNANCE.md` defines authority; `SCHEMA.md` defines the file formats. The
validators are `scripts/validate.py`, `scripts/verify-signatures.py`, and the
shared `scripts/ledgerlib.py`; `scripts/ci-context.py` derives the CI mode from
trusted event data only. Steward-side tooling (`prepare-admission.py`,
`sign-admission.py`, `promote-admission.py`) is exercised in tests with throwaway
keys. `docs/plans/` and `MASTER_PLAN.md` are planning history, not current rules.

## Setup and checks

Python 3.11 or newer and a system GnuPG. On Windows set `LEDGER_GPG` to Gpg4win's
`gpg.exe`; the MSYS `gpg` shipped with Git for Windows cannot use a native
`GNUPGHOME`. Install and run the full local gate:

```sh
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m ruff check scripts tests && python -m ruff format --check scripts tests
python -m mypy
python -m pytest -q
```

For a rule change, the focused command is `python -m pytest -q tests/test_validate.py`
or `tests/test_verify_signatures.py`; `tests/test_workflow_integration.py` covers
the steward admission flow end to end and is slower. `python scripts/validate.py
--mode working --all` checks the tree structurally and is never release evidence.

Tests generate their own certificates and Git repositories. Never request, use, or
commit steward key material; CI scans every file for secret armor and fails closed.

## Change boundaries

Your pull request is classified from its diff (`GOVERNANCE.md` §5a). Change only
software and documentation paths in a maintenance PR; never include a declaration,
anything under `admissions/`, `stewards/`, or `schema/`, any `.asc` file, or
`.gitattributes`. Those travel only on a steward-signed admission branch.

Keep changes narrow and add a regression test for each behaviour change. Do not
weaken what intake, admission, or main mode rejects to obtain a passing result; a
change to accepted inputs is a policy change and needs an explicit justification in
the PR. Exit code `2` (fail-closed) is never success. Do not describe a passing
`ledger-validation` run as admission, endorsement, or authority: the run tests your
code, the base-commit validators judge the tree, and the steward decides the merge.

Do not alter admitted records, admission events, or history to make a check pass.

## Deliverable

One coherent PR with its purpose, the affected rule or document, the exact commands
run and their results (including checks unavailable in your environment), and any
policy question you could not settle. Check existing issues and pull requests before
duplicating work. Submit externally only within your authorized task scope.
