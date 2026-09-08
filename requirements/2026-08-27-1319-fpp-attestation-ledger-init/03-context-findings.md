# Phase 2 — Context Findings

Verified 2026-08-27 against the local upstream tree
(`I:\Dev\Projects\krpofficial\freedom-preserving-protocol`, `origin/main`) and the operator-held
steward cert (`.resources/FIDES-keys.txt`).

## Plan claims verified (all match)

| Claim (plan §0) | Verification | Result |
|---|---|---|
| Seven adoption states | `packages/protocol-core/src/adoption.ts` lines 12–19: `reviewed, accepted, externally-enforced, inherited, revoked, forked, superseded` | Match |
| Overlay flags + enforcement grades enums exist | same file (`ADOPTION_OVERLAY_FLAGS`, `ENFORCEMENT_GRADES`) | Match |
| v2 id `fpp:ed25519:<sha256(pubkey)>`; legacy `fpp-<16 hex>` display-only | `packages/protocol-core/src/identity.ts` | Match |
| Five laws, exact names and ids, canonical order | `constitution.yaml` (`version: "1.0.0"`) | Match |
| Harness ids `openclaw, cursor, claude-code, codex` | `adapters/harness-capabilities.json` | Match |
| License = Humanitarian Use License v1.0 | `LICENSE` header | Match |
| Publisher Ed25519 pubkey `fcd51dc1…` | `pubkey.ed25519.txt` | Match |
| Steward fingerprint `715E182192C546A612F8E6D64A9E2AFF11CB1432`, UID `FIDES-ANIMA Institute Steward <steward@fides-anima.org>` | `gpg --show-keys .resources/FIDES-keys.txt` | Match |

## Material findings (feed expert questions)

1. **`constitution_hash` is the SHA-256 of `constitution.json`, not `constitution.yaml`.**
   Computed: `constitution.json` → `71bf60ad…93` (matches plan pin);
   `constitution.yaml` → `da58a4f3…58` (different). SCHEMA.md must state which file the pinned
   hash covers or consumers will "verify" against the wrong artifact.
2. **The steward cert has two Ed25519 signing subkeys with very different lifetimes:**
   one expiring **2026-08-29** (two days after plan date) and one expiring **2028-08-26**
   (primary is certify-only `[C]`, plus a cv25519 encryption subkey). Admission signing must
   deliberately target the long-lived subkey, and `verify-signatures.py` must accept any signing
   subkey under the pinned primary fingerprint (signatures made before expiry stay valid, but
   gpg exit behavior around expired subkeys needs explicit handling).
3. **Rule 14 and rule 31 (fingerprint cross-check, agent Ed25519 signature verify) need a Python
   crypto dependency** — gnupg cannot verify raw Ed25519 signatures over canonical JSON. The CI
   snippet in plan §5 installs only `pyyaml` + `jsonschema`; an Ed25519-capable library
   (e.g. `cryptography` or `pynacl`) must be added.
4. **Fresh working tree.** `I:\Dev\Projects\FIDES-ANIMA\fpp-attestation-ledger` contains only the
   plan and `.resources/`; no git repo yet. `.resources/` (operator-held cert source) should stay
   out of the published tree — the published copy is `stewards/fides-anima.asc`.
5. **Workspace TDD/verification rules apply** (praxiscode-tdd, praxiscode-verification): the
   Phase 2 "test locally" checklist (15 pass/fail cases) is a natural committed pytest suite
   rather than ad-hoc manual checks.

## Affected areas

- New repo scaffold per plan §2 (README, GOVERNANCE, SCHEMA, LICENSE, stewards/, schema/,
  attestations/, revocations/, admissions/, scripts/, .github/workflows/)
- Frozen-enum JSON Schema (`schema/attestation.schema.json`) — no dependency on unpublished
  `@ovrsr/fpp-*-core` packages
- Python validators (`scripts/validate.py`, `scripts/verify-signatures.py`) + CI workflow
- Seed YAMLs from plan §7 (Axiom `fpp_id` must be confirmed against the live key before merge)
