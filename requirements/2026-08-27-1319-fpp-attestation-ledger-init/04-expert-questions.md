# Phase 2 — Expert Questions

Five technical yes/no questions informed by context findings. Answer `yes` / `no` / `idk`
(idk = accept the default). Served in bulk at user request.

## Q1

Should SCHEMA.md and the validator explicitly document that `adoption.constitution_hash` is the
SHA-256 of **`constitution.json`** (verified: `71bf60ad…93` matches the JSON; the YAML hashes to
`da58a4f3…58`)?

**Default: Yes** — consumers who hash the YAML would get a false mismatch; the pin stays a frozen
literal either way.

## Q2

Should steward admissions be signed exclusively with the **long-lived signing subkey (expires
2028-08-26)** — never the subkey expiring 2026-08-29 — while `verify-signatures.py` accepts any
signing subkey belonging to the pinned primary fingerprint `715E1821…1432`?

**Default: Yes** — signatures from the short-lived subkey would trigger expiry warnings within
days; pinning verification to the primary fingerprint keeps subkey rotation possible.

## Q3

Should `scripts/verify-signatures.py` shell out to system `gpg` using an ephemeral temporary
`GNUPGHOME` (import pinned cert, verify, discard), rather than using a pure-Python OpenPGP
library?

**Default: Yes** — CI already installs gnupg (plan §5); an ephemeral home avoids keyring
pollution and third-party OpenPGP-parsing dependencies.

## Q4

Should the repo pin its toolchain with a committed `requirements.txt` (pinned `pyyaml`,
`jsonschema`, plus `cryptography` for Ed25519 verification and fingerprint cross-checks in rules
14/31) and Python 3.11 in CI?

**Default: Yes** — rules 14 and 31 cannot be implemented with gnupg alone; unpinned deps make CI
results non-reproducible.

## Q5

Should the Phase 2 "test locally" checklist (15 must-pass/must-fail cases from plan §8) be
implemented as a committed pytest suite that runs in the CI workflow, per the workspace TDD rule?

**Default: Yes** — encodes the acceptance criteria permanently; manual ad-hoc testing would
violate praxiscode-tdd/verification and rot immediately.
