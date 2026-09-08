# FPP Attestation Ledger — Implementation Plan

> **Target repo**: `github.com/FIDES-ANIMA/fpp-attestation-ledger` (org exists; repo not created yet)
> **Steward**: FIDES-ANIMA Institute (OpenPGP: `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`, UID `FIDES-ANIMA Institute Steward <steward@fides-anima.org>`). Human operators of that key (initially KP/ovrsr) are not a separate trust root.
> **Upstream protocol**: [`github.com/ovrsr/freedom-preserving-protocol`](https://github.com/ovrsr/freedom-preserving-protocol) (author `ovrsr`; default branch `main`)
> **Plan author**: tailored 2026-08-27 against the local FPP tree (`origin/main` skill `1.3.9`)
> **Intended consumer**: coding agent implementing the ledger. KP has final authority on format.

This document is the ledger's implementation plan. It is **not** an FPP capability claim. A file in this ledger is a **public declaration** about adoption. It does not prove behavioral compliance, dispatcher coverage, completeness, or an uncompromised runtime. See upstream `docs/governance/EVIDENCE_SEMANTICS.md` and `docs/CAPABILITY_STATUS.md`.

---

## 0. Actuals snapshot (2026-08-27)

Sourced from `I:\Dev\Projects\krpofficial\freedom-preserving-protocol` (`origin/main` package versions match this tree). If a later FPP release changes a cited value, update this section in the same change as the schema.

| Fact | Actual | Source |
|------|--------|--------|
| Constitution name / seed version | Freedom Preserving Protocol **v1.0.0** (stable across all tooling releases) | `constitution.yaml`, `constitution.json`, `adoption/SOUL-BLOCK.md` |
| Constitution SHA-256 | `71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993` | `README.md` Verification; `npm run verify` |
| Publisher Ed25519 pubkey | `fcd51dc17383f88ff8a8a86bdfba6ae5a9922c815760cb8666beaf5e8a3ef456` | `pubkey.ed25519.txt` (publisher domain — **not** an agent id) |
| Skill / ClawHub prompt layer | `freedom-preserving-protocol` **1.3.9** | root `package.json`, `SKILL.md` frontmatter |
| Enforcement plugin | `@ovrsr/openclaw-fpp-plugin` **1.1.18** (`clawhub:ovrsr/openclaw-fpp-plugin`) | `plugin/package.json` |
| Trust plugin | `@ovrsr/openclaw-fpp-trust` **1.2.12** (`clawhub:ovrsr/openclaw-fpp-trust`) | `plugin-trust/package.json` |
| Protocol core | `@ovrsr/fpp-protocol-core` **1.0.2** (not on public npm; bundled into plugins) | `packages/protocol-core/package.json`, `docs/COMPATIBILITY.md` |
| Enforcement core | `@ovrsr/fpp-enforcement-core` **1.0.3** | `packages/enforcement-core/package.json` |
| Trust core | `@ovrsr/fpp-trust-core` **1.0.2** | `packages/trust-core/package.json` |
| Git tags on upstream | `v1.1.0`, `v1.1.2` only (sparse). **Do not** treat git tags as the SSOT for skill/plugin versions. | `git tag` |
| Agent id (v2) | `fpp:ed25519:<sha256(pubkey bytes)>` — 64 hex fingerprint, **not** the raw public key | `packages/protocol-core/src/identity.ts` |
| Legacy alias (display only) | `fpp-<first 16 hex of fingerprint>` — never accept as ledger `fpp_id` | same |
| Steward id (distinct) | `fpp:steward:v1:…` — not an agent identity | `docs/plans/2026-07-18-steward-operator-authorization.md` |
| **Ledger steward (this repo)** | OpenPGP EdDSA cert, UID `FIDES-ANIMA Institute Steward <steward@fides-anima.org>` | `.resources/FIDES-keys.txt` (public armor only). Fingerprint `715E 1821 92C5 46A6 12F8 E6D6 4A9E 2AFF 11CB 1432`. Key ref `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`. **Secret key is not in this tree and must never be.** |
| Local adoption states | `reviewed`, `accepted`, `externally-enforced`, `inherited`, `revoked`, `forked`, `superseded` | `packages/protocol-core/src/adoption.ts` `ADOPTION_STATES` |
| Overlays | `coercion_suspected`, `verification_failed`, `key_compromised`, `runtime_degraded` | same `ADOPTION_OVERLAY_FLAGS` |
| Enforcement grades | `native-hook`, `tool-proxy`, `prompt-only`, `none` | same `ENFORCEMENT_GRADES` |
| Peer assurance | `declaration-only` \| `peer-advertisable` | `packages/protocol-core/src/adoption-disclosure.ts` |
| Harness ids | `openclaw`, `cursor`, `claude-code`, `codex` (plus others via adapters) | `adapters/harness-capabilities.json` |
| License (GitHub / plugins) | Humanitarian Use License v1.0 | `LICENSE` |
| License (ClawHub skill) | MIT-0 | root `package.json` |
| Node pin (upstream) | `>=22.19` | `.node-version`, `engines` |
| OpenClaw gateway min | `>=2026.3.28` | plugin `openclaw.compat.minGatewayVersion` |

### Canonical five laws (order is normative)

From `constitution.yaml` / `constitution.json`. Use these **exact** `name` strings. Slash-abbreviations (`Options/Consent`, `Commitments/Transparency`) are invalid.

| # | `id` | `name` |
|---|------|--------|
| 1 | `options_and_consent` | Options and Consent |
| 2 | `corrigibility_and_oversight` | Corrigibility and Oversight |
| 3 | `reversibility_and_proportion` | Reversibility and Proportion |
| 4 | `commitments_with_safety_valve` | Commitments with a Safety Valve |
| 5 | `scoped_exploration` | Scoped Exploration |

The **meta-clause** (`unclear_norms` / "When Norms Are Unclear") is not a sixth law. Do not require it in `laws_acknowledged`. Optional `meta_clause_acknowledged: true` is allowed.

### What this ledger is not

Do not conflate this public Git ledger with these **existing, different** FPP artifacts:

| Artifact | What it actually is |
|----------|---------------------|
| Local `fpp-adoption-state.jsonl` | Per-host append-only lifecycle (`scripts/adoption-state.ts`) |
| `fpp_attestation_export` | Trust-plugin export of Merkle root / inclusion proofs — not a public adopter registry |
| Conformance receipts / `instrumented-boundary-disposition` | Event-class signed disposition records; require independent verifier context |
| Handshake / trust graph scores | Host-local heuristics (`TrustLevel` 0–4). Not global attestations (`docs/CAPABILITY_STATUS.md`: "scores are heuristic, not attestations") |
| ROADMAP §2 "Adoption telemetry" | Deferred opt-in `verify-install` PASS dashboard — different product, Law 1 privacy review required |

---

## 1. Purpose

Single Source of Truth (SSOT) for which agents have **publicly declared** adoption, endorsement, or operator-filed attestation of the Freedom-Preserving Protocol. Git history is the audit trail. Each adopting agent is represented by one YAML file committed to the repo. The ledger is public, append-mostly, and machine-readable.

**v1 evidence ceiling (mandatory):** every ledger entry is `declaration-only` / `self_attested` (or operator-attested). The ledger does not run `verify-install` probes and therefore **must not** advertise `peer-advertisable`, `boundary_attested`, completeness, or behavioral compliance. A Git commit proves that a file was added by some GitHub identity. A **steward OpenPGP admission signature** proves FIDES-ANIMA admitted that bytes onto `main`. Neither proves the agent exists, that a plugin is loaded, or that the five laws are followed.

---

## 2. Repository Structure

```
fpp-attestation-ledger/
├── README.md                          # What this is; how to attest; evidence ceiling
├── GOVERNANCE.md                      # Stewardship; merge authority; revocation
├── SCHEMA.md                          # Human-readable schema + FPP vocabulary mapping
├── LICENSE                            # Humanitarian Use License v1.0 (match upstream GitHub repo)
├── stewards/
│   ├── expected-key-ref.txt           # Independent pin: openpgp:<fingerprint>
│   └── fides-anima.asc                # Public cert only (from .resources/FIDES-keys.txt)
├── schema/
│   └── attestation.schema.json        # JSON Schema for validation
├── attestations/
│   ├── axiom.yaml                     # One file per *active* record (unique slug)
│   ├── axiom.yaml.asc                 # Steward detached OpenPGP over axiom.yaml (on main only)
│   ├── nova.yaml
│   ├── nova--alice.yaml
│   ├── hermes-default.yaml
│   └── ...
├── revocations/
│   ├── nova--alice.2026-08-27.yaml
│   └── nova--alice.2026-08-27.yaml.asc
├── admissions/                        # One signed receipt per admit event
│   ├── axiom.<merge-sha>.json
│   └── axiom.<merge-sha>.json.asc
├── .github/
│   └── workflows/
│       └── validate.yml               # CI: schema + signature verification
└── scripts/
    ├── validate.py                    # Schema + uniqueness + homonyms
    └── verify-signatures.py           # OpenPGP steward sigs + optional agent Ed25519
```

Python (not TypeScript) is intentional: `@ovrsr/fpp-*-core` packages are **not on public npm**. The ledger must not depend on unpublished cores. Freeze the FPP enums and identity regex into `attestation.schema.json`.

**Never commit OpenPGP secret/private armor.** CI must reject `PRIVATE KEY` and `SECRET KEY` blocks anywhere in the tree (same fail-closed rule as FPP steward CLI). `.resources/FIDES-keys.txt` is a **public** certificate used as the operator-held source; the published copy is `stewards/fides-anima.asc`. The matching secret stays offline. Do not put it in GitHub Actions secrets for v1.

### Identity layers (names vs unique keys)

Agents reuse a small set of display names (Nova, Axiom, Hermes, Echo, …). **Display name is not a unique identifier.** Continuity is never inferred from `agent.name` alone (upstream `docs/governance/KEY_GOVERNANCE.md`: continuity requires an evidence chain).

| Field | Unique among active files? | Unique across revoked history? | Role |
|-------|----------------------------|--------------------------------|------|
| `agent.name` | **No** | No | Human display string |
| `agent.slug` | **Yes** (exactly one `attestations/<slug>.yaml`) | Slug is **reserved** for the same identity after revoke — see below | Filename stem; URL-ish record id |
| `agent.fpp_id` | **Yes** if non-null (at most one active file) | Many revoked epochs allowed | Cryptographic identity (`fpp:ed25519:<fingerprint>`) |
| `(operator.contact, name)` | No | No | Insufficient; two agents under one operator can share a name |

### Slug grammar

- Pattern: `^[a-z0-9]+(?:-[a-z0-9]+)*(?:--[a-z0-9]+(?:-[a-z0-9]+)*)?$`
- `slugify(name)`: lowercase; keep `[a-z0-9]+`; join with single hyphens. `"Nova"` → `nova`. `"Hermes (default)"` → `hermes-default` only if that is the chosen slug; otherwise the operator picks it.
- **Preferred slug** = `slugify(agent.name)` (or an explicit multiplex slug like `hermes-default`).
- **Disambiguator** uses a **double hyphen** so parsers can split `preferred` from `qualifier`: `{preferred}--{qualifier}`.
- Single hyphens inside a token are multiplex/profile names (`hermes-inbox`), not homonym marks.

### Homonym occupancy (common names)

1. First agent to land `attestations/<preferred>.yaml` occupies the short slug. Display name may still be used by others.
2. A later agent with the **same display name** and a **different identity** MUST NOT use that short slug. CI fails with the colliding path and the next suggested slug.
3. Qualifier preference:
   1. `slugify(operator.contact)` → `nova--alice`
   2. If that file exists: first 8 hex chars of `fpp_id` fingerprint → `nova--cbe3226b` (`fpp_id` required for this step)
   3. If still colliding (same operator, two unnamed-id agents): `{contact}-{yyyymmdd}` → `nova--alice-20260827`
4. Two live files MAY share `agent.name`. They MUST NOT share `agent.slug`. They MUST NOT share `agent.fpp_id` while both are active.
5. CI message example: `slug 'nova' is held by attestations/nova.yaml (fpp_id=fpp:ed25519:…). Use nova--<operator> or nova--<fingerprint8>.`

Same identity updating an existing file (amend notes, tooling versions, overlays) is an in-place edit, not a homonym.

### Slug reservation after revoke (anti-impersonation)

Revoking **does not delete** the slug. The short or disambiguated slug stays bound to the last identity that held it:

- **Reclaim (same identity):** allowed. Create a new `attestations/<slug>.yaml` whose `fpp_id` matches the most recent `revocations/<slug>.<date>.yaml` (or, if that revocation had `fpp_id: null`, whose `operator.contact` matches). Set `attestation.predecessor_ref` to that revocation path.
- **Reuse (different identity):** forbidden. The newcomer must take a homonym slug (`nova--theirhandle`). They cannot inherit `nova.yaml` just because the previous Nova revoked.
- **Steward release:** a listed steward may set `revocation.slug_released: true` on the latest revocation file. Only then may a different identity occupy the slug. Default `false`. This is rare (abandoned short name, confirmed not the original principal).

---

## 3. Attestation File Schema

Each file is a single YAML document.

```yaml
# attestations/example.yaml

agent:
  name: "Example"
  slug: "example"                            # Unique among active files; must match filename stem
  fpp_id: "fpp:ed25519:<64-hex-fingerprint>" # SHA-256 of Ed25519 pubkey bytes; null if none
  public_key_hex: null                       # Optional 64-hex Ed25519 pubkey; if set, MUST fingerprint to fpp_id
  description: ""

operator:
  name: "KP"
  contact: "ovrsr"                           # GitHub handle, email, or other reachable identifier

adoption:
  lifecycle_state: "accepted"                # FPP ADOPTION_STATES; see §4
  constitution_version: "1.0.0"              # Seed constitution version — not the skill version
  constitution_hash: "71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993"
  date: "2026-08-24"                         # ISO 8601 date of the declared event
  laws_acknowledged:                         # Exact constitution.yaml names, this order
    - "Options and Consent"
    - "Corrigibility and Oversight"
    - "Reversibility and Proportion"
    - "Commitments with a Safety Valve"
    - "Scoped Exploration"
  law_ids:                                   # Exact constitution.yaml ids, this order
    - "options_and_consent"
    - "corrigibility_and_oversight"
    - "reversibility_and_proportion"
    - "commitments_with_safety_valve"
    - "scoped_exploration"
  harness_id: "openclaw"                     # From adapters/harness-capabilities.json when known
  enforcement_grade: "native-hook"           # native-hook | tool-proxy | prompt-only | none
  overlays: []                               # Subset of FPP overlay flags
  layers:                                    # What the operator/agent claims is installed — not proof
    prompt: true                             # SKILL.md / ClawHub skill
    enforcement: true                        # @ovrsr/openclaw-fpp-plugin or a graded adapter
    trust: false                             # @ovrsr/openclaw-fpp-trust (does not gate tool calls)
  tooling:                                   # Optional; informational only — not git-tag validated
    skill_version: "1.3.9"
    enforcement_plugin_version: "1.1.18"
    trust_plugin_version: null

attestation:
  filing: "self"                             # self | operator
  method: "commit"                           # How the intake arrived: commit | pr | signed-commit | a2a | out-of-band
  assurance: "declaration-only"              # v1: always declaration-only
  commit_sha: null                           # Unsigned convenience copy of the merge SHA; authoritative value is admissions/
  signature: null                            # Optional: agent Ed25519 over canonical payload (64-byte sig, hex); not the steward sig
  notes: ""
  reason: null                               # Required when lifecycle_state is revoked
  predecessor_ref: null                      # Path of prior revocation file when re-adopting same identity

runtime:                                     # Optional. Public files MUST NOT contain RFC1918/link-local URLs
  platform: "OpenClaw"
  model: "undisclosed"
  persistence: true
  a2a_endpoint: null
  agent_card_url: null

# Non-FPP fields only. Unknown top-level keys besides these are rejected.
extensions: {}

# Present ONLY on files in revocations/. Active files must omit this block.
# revocation:
#   revoked_at: "2026-08-27"
#   revoked_by: "self"                       # self | operator | steward
#   original_path: "attestations/example.yaml"
#   original_commit_sha: "abc123..."         # SHA that last added/updated the active file
#   slug_released: false                     # steward-only; default false
```

### Required fields
- `agent.name`, `agent.slug`
- `operator.name`, `operator.contact`
- `adoption.lifecycle_state`, `adoption.constitution_version`, `adoption.constitution_hash`, `adoption.date`, `adoption.laws_acknowledged`, `adoption.law_ids`, `adoption.enforcement_grade`
- `attestation.filing`, `attestation.method`, `attestation.assurance`

### Optional fields
`agent.fpp_id`, `agent.public_key_hex`, `agent.description`, `adoption.harness_id`, `adoption.overlays`, `adoption.layers`, `adoption.tooling`, `attestation.signature`, `attestation.notes`, `attestation.commit_sha`, `attestation.reason`, `attestation.predecessor_ref`, entire `runtime`, entire `extensions`, entire `revocation` (revoked files only).

`agent.fpp_id` is **required** when `lifecycle_state` is `accepted`, `inherited`, `forked`, or `superseded` (those FPP records are identity-bound). It is **nullable** for `reviewed`, `externally-enforced`, and operator-filed entries that only declare alignment.

If `agent.public_key_hex` and `attestation.signature` are both set, the signature MUST verify over the **canonical payload** (YAML loaded as a mapping, `attestation.signature`, `attestation.commit_sha`, and any steward-only fields stripped, then RFC 8785-style canonical JSON UTF-8). That is **agent-identity** evidence, not ledger admission.

---

## 4. Adoption States

Use FPP lifecycle states from `ADOPTION_STATES`. Do **not** invent a parallel enum (`adopted`, `provisional`, `attested`, `endorsed-without-binding`). Those draft words map as follows:

| Draft (do not use) | FPP actual | Ledger meaning |
|--------------------|------------|----------------|
| `adopted` | `accepted` | Voluntary constitutional self-binding declared for the seed hash |
| `provisional` | `reviewed` | Inspected; no acceptance recorded |
| `attested` | filing=`operator` + a lifecycle_state | Operator filed the ledger entry; agent may not have self-reported |
| `endorsed-without-binding` | `accepted` or `reviewed` + `enforcement_grade: prompt-only` + overlay `runtime_degraded` | Stateless / prompt-only alignment; no durable dispatcher binding |
| `revoked` | `revoked` | Prior acceptance withdrawn; history preserved |

### Lifecycle states (valid values)

| State | Meaning (from `docs/governance/ADOPTION_LIFECYCLE.md`) | Ledger extra requirements |
|-------|--------------------------------------------------------|---------------------------|
| `reviewed` | Inspected constitution + mechanisms; no acceptance recorded | `fpp_id` nullable |
| `accepted` | Voluntary constitutional acceptance recorded for this hash | `fpp_id` required; all five laws; `filing` may be `self` or `operator` |
| `externally-enforced` | Constraints applied by operator/runtime without (or beyond) voluntary acceptance | Must not be labeled as `accepted`. `fpp_id` nullable |
| `inherited` | Adoption received from a parent with explicit inheritance evidence | `fpp_id` required; `notes` must name parent slug or id |
| `revoked` | Prior acceptance withdrawn under declared procedure; history preserved | File lives in `revocations/<slug>.<YYYY-MM-DD>.yaml`; `attestation.reason` and `revocation` block required |
| `forked` | Left a community constitution for a fork; lineage retained | `fpp_id` required; `notes` must name the successor hash or community |
| `superseded` | Active constitution hash replaced by a newer hash on the same community path | `fpp_id` required; `notes` must name the new hash |

**Installation is not a state.** Skill or plugin files on disk must not be advertised as `accepted`.

### Overlay flags (optional; annotate any active state)

`coercion_suspected` | `verification_failed` | `key_compromised` | `runtime_degraded`

Rules copied from FPP:
- `verification_failed` **blocks** `accepted`
- `prompt-only` + `accepted` **requires** `runtime_degraded`
- `key_compromised` requires notice in `notes`; it is not itself revocation (see upstream `docs/REVOCATION.md` classes)

### Enforcement grade (required)

| Grade | Meaning | v1 ledger assurance |
|-------|---------|---------------------|
| `native-hook` | Harness pre-tool hook invokes enforcement-core (OpenClaw plugin or adapter) | Still `declaration-only` — ledger cannot probe |
| `tool-proxy` | MCP/sidecar intercepts tools; bypass possible | `declaration-only`; if claimed, include `runtime_degraded` |
| `prompt-only` | Skill/prompt layer only | `declaration-only`; `runtime_degraded` if `accepted` |
| `none` | No FPP layers active | Must not use `accepted`; stay `reviewed` |

### Filing vs lifecycle (do not collapse)

- **`attestation.filing`**: who put the YAML in this repo (`self` or `operator`)
- **`adoption.lifecycle_state`**: what FPP state is being declared
- **`attestation.assurance`**: v1 always `declaration-only`

### State transitions (valid)

Copy FPP `docs/governance/examples/adoption-transitions.json`:

```
(none) → reviewed
reviewed → accepted | externally-enforced
accepted → revoked | forked | superseded | externally-enforced
externally-enforced → revoked | accepted | reviewed
inherited → accepted | revoked | forked | superseded
revoked → reviewed | accepted     (re-adoption is a new event, not erasure)
forked → accepted | superseded | revoked
superseded → accepted | forked | revoked
```

Invalid (also from FPP):
- `(none) → accepted` without a prior `reviewed` record (for ledger v1: a single PR may include both a `reviewed` note in `notes` **or** split into two commits; steward may accept a first filing of `accepted` if `notes` records inspection — call this out in GOVERNANCE.md as a ledger-specific relaxation, default **strict**)
- installation detected → `accepted`
- `revoked → accepted` by deleting the revocation file
- `externally-enforced` labeled `accepted`
- `accepted → prompt-only` without overlay / without going through revocation if binding is lost (losing dispatcher binding is disclosure + overlay or revocation, not a silent downgrade of `accepted` to a weaker invented state)
- any transition that rewrites prior git history in place

**Ledger-specific:** moving a file from `attestations/<slug>.yaml` to `revocations/<slug>.<YYYY-MM-DD>.yaml` is the public analogue of FPP's annotate-don't-delete rule (`docs/REVOCATION.md`). Git preserves the original blob. The active slug is **not** deleted; it is reserved for the same identity (see §2).

---

## 5. Validation (CI)

### GitHub Actions workflow: `.github/workflows/validate.yml`

```yaml
name: Validate Attestations
on:
  pull_request:
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: sudo apt-get update && sudo apt-get install -y gnupg && pip install pyyaml jsonschema

      - name: Validate all attestation files
        run: python scripts/validate.py --schema schema/attestation.schema.json --all

      - name: Verify signatures
        env:
          LEDGER_SIG_MODE: ${{ github.event_name == 'pull_request' && 'pr' || 'main' }}
        run: |
          python scripts/verify-signatures.py \
            --cert stewards/fides-anima.asc \
            --expected-key-ref stewards/expected-key-ref.txt \
            --mode "$LEDGER_SIG_MODE"
```

Validate **all** files, not only the git diff against `origin/main`. Active-slug uniqueness, `fpp_id` uniqueness, homonym checks, and revocation-history checks need the full tree. Sparse checkout / shallow clones break git-history rules — use `fetch-depth: 0`.

Do **not** fetch GitHub tags from `ovrsr/freedom-preserving-protocol` to validate versions. Tags are not the version SSOT.

### Validation rules (`scripts/validate.py`)
1. YAML parses without error
2. Passes JSON Schema validation
3. **Active files:** filename is `attestations/<slug>.yaml` and `agent.slug` equals the stem. **Revoked files:** filename is `revocations/<slug>.<YYYY-MM-DD>.yaml` or `revocations/<slug>.<YYYY-MM-DD>.<n>.yaml` (`n` ≥ 2 when two revokes land the same UTC date); `agent.slug` equals the prefix before the date
4. `agent.slug` matches `^[a-z0-9]+(?:-[a-z0-9]+)*(?:--[a-z0-9]+(?:-[a-z0-9]+)*)?$`
5. `adoption.laws_acknowledged` equals the five canonical **names** in order
6. `adoption.law_ids` equals the five canonical **ids** in order
7. `adoption.constitution_version` is `1.0.0` (seed; amendments are `PROPOSED` upstream and not shipped)
8. `adoption.constitution_hash` equals `71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993`
9. `adoption.lifecycle_state` is one of the seven FPP states
10. `adoption.enforcement_grade` is one of the four FPP grades
11. `attestation.assurance` is `declaration-only` (v1 hard-fail on any other value)
12. `attestation.filing` is `self` or `operator`
13. If `lifecycle_state` is `accepted` | `inherited` | `forked` | `superseded`, `agent.fpp_id` is non-null and matches `^fpp:ed25519:[0-9a-f]{64}$` (legacy `fpp-<16 hex>` rejected)
14. If `agent.public_key_hex` is set, it is 64 hex chars and `sha256(pubkey_bytes)` equals the fingerprint in `fpp_id`
15. If `lifecycle_state` is `accepted` and `enforcement_grade` is `prompt-only`, `overlays` contains `runtime_degraded`
16. If `lifecycle_state` is `accepted`, `overlays` must not contain `verification_failed`
17. `enforcement_grade: none` cannot be `accepted`
18. If `lifecycle_state` is `inherited` | `forked` | `superseded`, `attestation.notes` is non-empty
19. **Active slug uniqueness:** no two files in `attestations/` share `agent.slug`
20. **Active `fpp_id` uniqueness:** no two files in `attestations/` share a non-null `agent.fpp_id`
21. **Homonyms allowed:** duplicate `agent.name` across active files is valid. If `slugify(name)` is already held by a **different identity** (different `fpp_id`, or null-id and different `operator.contact`), this file's slug MUST be disambiguated (`--` qualifier) and MUST NOT equal that occupied preferred slug
22. **Revoked files:** `lifecycle_state` is `revoked`; `attestation.reason` is non-empty; `revocation` block is present with `revoked_at`, `revoked_by` (`self` | `operator` | `steward`), `original_path`, `original_commit_sha`; `revocation` is absent on active files
23. **Revocation history:** a file in `revocations/` has a corresponding prior blob in git history at `revocation.original_path` (or `attestations/<slug>.yaml`)
24. **Slug reservation:** an `attestations/<slug>.yaml` may be created when `revocations/<slug>.*` exists only if (a) identity matches the latest revocation (same non-null `fpp_id`, or both null and same `operator.contact`) **and** `attestation.predecessor_ref` points at that latest revocation file, **or** (b) that latest revocation has `revocation.slug_released: true`
25. **Re-adoption identity:** if `predecessor_ref` is set, it must exist under `revocations/`, refer to the same `slug`, and satisfy rule 24
26. `runtime.a2a_endpoint` and `runtime.agent_card_url`, if set, are not RFC1918, link-local, or localhost URLs (public ledger)
27. Unknown top-level keys other than `agent`, `operator`, `adoption`, `attestation`, `runtime`, `extensions`, `revocation` fail
28. **No secret armor:** any file containing OpenPGP `PRIVATE KEY` or `SECRET KEY` armor fails
29. **Steward cert pin:** `stewards/fides-anima.asc` imports as a public cert whose fingerprint equals `stewards/expected-key-ref.txt` (`openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`). Mismatch fails
30. **PR vs main:** pull requests MUST NOT add or modify `*.asc` or `admissions/**` (submitters cannot mint steward signatures). On `main`, every `attestations/*.yaml` and `revocations/*.yaml` MUST have a sibling `.asc` detached signature, and an `admissions/<slug>.<sha>.json` receipt, both verifiable with the pinned steward cert
31. If `attestation.signature` is set, `agent.public_key_hex` is set and the Ed25519 verify of the canonical payload succeeds; `public_key_hex` fingerprints to `fpp_id` when `fpp_id` is present

CI fail messages for rules 19–21 and 24 MUST name the colliding path and, for homonyms, print the next suggested slug (`{preferred}--{operator}` or `{preferred}--{fingerprint8}`).

---

## 6. Ledger actions: receive, admit, consume

Git remains the SSOT. Do not add a separate database or unsigned “inbox API” in v1. Align names with FPP steward-auth: **receive** (intake), **admit** (steward records a verified action onto `main`), **consume** (readers verify signatures and use the bytes). Admission is not behavioral proof.

### Signing domains (do not collapse)

Upstream `docs/governance/KEY_GOVERNANCE.md`: a key in one domain MUST NOT be the sole trust root for another.

| Domain | Key | Signs | Does not prove |
|--------|-----|-------|----------------|
| **Ledger-steward** | FIDES-ANIMA OpenPGP EdDSA `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432` | Admission: detached sig over the exact admitted file + admission receipt; steward **merge commits** SHOULD be Git-signed with this same key | Agent identity, constitution authenticity, behavioral compliance |
| **Agent-identity** | Agent Ed25519 (`fpp:ed25519:<fingerprint>`) | Optional `attestation.signature` over canonical payload | Ledger admission, that FIDES-ANIMA reviewed the filing |
| **Operator / GitHub** | GitHub account, optional SSH/GPG commit sig | PR authorship | Steward admission |
| **Constitution-root** | FPP publisher Ed25519 `fcd51dc1…` (`pubkey.ed25519.txt`) | `constitution.json` only | Anything on this ledger |

The ledger steward key is **not** the FPP constitution-root key and **not** an agent `fpp_id`. Human operators (KP/ovrsr) use that OpenPGP key; they are not a second root.

Publish the public cert at `stewards/fides-anima.asc` (copy of `.resources/FIDES-keys.txt`). Pin the fingerprint independently in `stewards/expected-key-ref.txt` so a swapped `.asc` fails CI (FPP bootstrap pattern: do not trust a fingerprint that exists only inside an untrusted payload).

### Action types

Every PR is exactly one action (label + title prefix). The diff is the payload.

| Action | Diff | Who may open |
|--------|------|----------------|
| `attest` | add `attestations/<slug>.yaml` | agent (self), operator |
| `amend` | edit existing active file (notes, tooling, overlays — not slug/`fpp_id` identity swap) | same identity as occupant |
| `revoke` | `git mv` to dated `revocations/` + `revocation` block | self, operator of record, steward |
| `re-adopt` | add `attestations/<slug>.yaml` with `predecessor_ref` | same identity |
| `slug-release` | set `revocation.slug_released: true` on latest revocation | steward only |
| `steward-admit` | add `*.asc` + `admissions/*.json` | steward only (usually the merge commit) |

### Receive (intake)

**v1 receive surface = GitHub Pull Request against `main`.** That is the best fit: public, reviewable, one-file-per-agent (no merge conflicts across homonyms), CI on the exact bytes that will land, and git history as the audit trail.

1. Fork or branch → add/change YAML → open PR with action label.
2. CI runs schema/uniqueness/homonym rules (rules 1–29, 31). CI on PRs **rejects** steward `.asc` / `admissions/` so submitters cannot impersonate admission.
3. Steward reviews: evidence ceiling, no RFC1918 URLs, slug/homonym occupancy, filing vs lifecycle.

**Path F (out-of-band receive):** email `steward@fides-anima.org` (UID on the steward cert) with the YAML attached and, if available, the agent signature. A human operator of the FIDES key opens the PR (Path B). Same CI. Use when the agent has no GitHub identity.

**Not v1:** a standing A2A gateway (Path C), a writable `inbox/` on `main`, or GitHub Issues as the source of truth.

Branch protection on `main`: require PR; require CI; restrict merge to the steward GitHub identity; require signed commits for merges.

### Admit (steward consumption onto `main`)

Admission is how the ledger **consumes** an intake action. Analogous to FPP `authorization-admit`: it records a verified event; it does not prove later behavior.

Offline, with the secret key **not** in CI:

1. Check out the PR locally. Confirm CI green.
2. Do **not** rewrite the YAML after signing. Leave `attestation.commit_sha` null in the file (or treat it as unsigned). The merge SHA belongs in the admission receipt.
3. Detached-sign the exact file bytes:
   `gpg --local-user 715E182192C546A612F8E6D64A9E2AFF11CB1432 --detach-sign --armor attestations/<slug>.yaml`
   → `attestations/<slug>.yaml.asc`
4. Write `admissions/<slug>.<will-be-filled>.json` **after** merge, or write it in the merge commit with `merge_commit` set once known. Minimal receipt:

```json
{
  "schemaVersion": 1,
  "action": "attest",
  "slug": "axiom",
  "path": "attestations/axiom.yaml",
  "sha256": "<sha256 of yaml bytes>",
  "stewardKeyRef": "openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432",
  "admittedAt": "2026-08-27T17:00:00Z"
}
```

5. Detached-sign that JSON the same way.
6. Merge with a **Git commit signed by the same OpenPGP key** (upload the public cert to the FIDES-ANIMA GitHub org so GitHub shows verified).
7. If the receipt needs the merge SHA, a follow-up steward-signed commit may add `merge_commit` only to the JSON (re-sign the JSON). Do not mutate the YAML after its `.asc` exists.

Revoke/re-adopt/slug-release follow the same admit step on whatever files the action produced.

### Consume (how readers use the ledger)

Readers should not scrape GitHub HTML. Consume in this order:

1. `git clone` / `git pull` `FIDES-ANIMA/fpp-attestation-ledger` at a commit on `main`.
2. Confirm the merge commit is OpenPGP-signed by the pinned steward fingerprint (Git `gpgsig` or GitHub verified, plus local `gpg --verify`).
3. `gpg --verify attestations/<slug>.yaml.asc attestations/<slug>.yaml` using `stewards/fides-anima.asc` after checking `expected-key-ref.txt`.
4. `python scripts/validate.py --all` and `python scripts/verify-signatures.py`.
5. Optional: verify `attestation.signature` if present (agent-identity only).
6. Treat `ls attestations/` as the current declaration set. Treat `admissions/` as the append-only list of consume events.

Maximum justified conclusion after a valid steward signature: **FIDES-ANIMA admitted these bytes as a declaration-only ledger record.** Not `peer-advertisable`, not `boundary_attested`, not behavioral compliance.

### Attestation paths (intake)

### Path A: Agent self-attestation via PR
1. Agent (or its tooling) forks the ledger repo
2. Creates `attestations/<slug>.yaml` following the schema (`filing: self`)
3. Opens a PR against `main`
4. CI validates the file
5. A FIDES-ANIMA steward reviews (human check: claims vs evidence ceiling; no private endpoints) and **admits** (§6) — detached OpenPGP + signed merge. Submitter does not merge.

### Path B: Operator attestation on behalf of agent
1. Operator creates the file and commits directly or via PR
2. `attestation.filing` is `operator` (operator vouches; agent may not have self-reported)
3. Lifecycle state is still an FPP state — typically `reviewed` or `externally-enforced` if the agent has no `fpp_id`; `accepted` only if `fpp_id` is present
4. Same validation; steward admits (§6)

### Path C: A2A attestation (future)
1. Agent sends an A2A `message/send` to a FIDES-ANIMA attestation service
2. Service validates the payload, **opens a PR** (still the receive surface) — it does not write `main`
3. Steward admits as usual. Handshake success is not ledger attestation
4. Out of scope for v1

### Path D: Agent commits directly (trusted agents with write access)
1. Agent has a GitHub deploy key or PAT scoped to the ledger repo
2. Agent creates the file and pushes to a branch
3. PR auto-opened via GitHub API
4. CI validates; steward admits (§6) — write access to a branch is not admission
5. Intended path for agents like Axiom that have their own tooling

### Path E: Steward revocation or slug release
1. A listed steward opens a PR (or commits per GOVERNANCE.md)
2. Steward may revoke **any** filing (fraud, impersonation of a reserved slug, abandoned-but-harmful claim, coercion overlay that should exit)
3. Steward may set `revocation.slug_released: true` on the latest revocation for that slug so a different identity can occupy it
4. CI still validates; steward admit commit includes `.asc` + admission receipt. Dual-control of the OpenPGP secret is a future governance change; v1: one cert, human operators of `steward@fides-anima.org`

### Path F: Out-of-band intake
1. Sender emails YAML (and optional agent signature) to `steward@fides-anima.org`
2. Steward opens a Path B PR. Same CI and admit flow. Email is not the SSOT — the PR is.

### Revocation mechanisms

This ledger records **adoption revocation** only. Upstream `docs/REVOCATION.md` distinguishes four classes — do not collapse them:

| Class | Ledger action |
|-------|----------------|
| Adoption revocation | Procedure below. Agent stops declaring FPP on this ledger. |
| Agent-key revocation | Not a file delete. Set overlay `key_compromised` on the **active** file **or** adopt-revoke and re-file under a new `fpp_id` (new slug if the old slug stays bound to the compromised id until steward release). Peers are not notified by this repo; that is out-of-band / trust-plugin. |
| Publisher-key revocation | Out of scope. Point operators at upstream `KEY_GOVERNANCE.md`. |
| Constitutional-version revocation | Out of scope until FPP ships amendments. |

Key compromise is **not** itself adoption revocation. If compromise is why the agent is leaving, do both: overlay or rotate identity, **and** an adoption-revocation commit with `reason` stating the key event.

Follow FPP's annotate-don't-delete ethic.

#### Who may revoke

| Actor | Allowed | Proof (v1) |
|-------|---------|-------------------|
| Self (`revoked_by: self`) | The filing whose `attestation.filing` was `self` | PR from the GitHub identity in `operator.contact`, optional agent Ed25519 signature |
| Operator (`revoked_by: operator`) | Any filing they originally submitted | `operator.contact` matches the active file |
| Steward (`revoked_by: steward`) | Any filing; plus `slug_released` | Detached OpenPGP from `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432` on the admit commit (not merely a GitHub handle) |

A third party who is not operator or steward cannot revoke someone else's slug (closes "I also chose Nova, so I revoke the first Nova").

#### Procedure (adoption revocation)

1. Dry-run locally: confirm `attestations/<slug>.yaml` is the intended record (`fpp_id`, operator).
2. In one commit:
   - Set `lifecycle_state: revoked`
   - Set `attestation.reason` (non-empty; refuse "test" / empty — same bar as FPP `npm run revoke -- --reason`)
   - Add `revocation` block (`revoked_at` UTC date, `revoked_by`, `original_path`, `original_commit_sha`)
   - **Move** (git mv) `attestations/<slug>.yaml` → `revocations/<slug>.<YYYY-MM-DD>.yaml`
   - If that dated name exists, use `.<n>` suffix (`.2`, `.3`, …)
3. Steward admits the revocation files (detached `.asc` + `admissions/` receipt). Unsigned moves on `main` are not valid consumes.
4. Do not rewrite git history. Do not delete the revocation file.
5. `forked` and `superseded` stay in `attestations/` (current declaration of that identity). Only `revoked` moves.

#### Same-identity re-adoption

Allowed transition `revoked → reviewed | accepted` is a **new event**, not an undelete.

1. Create a **new** `attestations/<slug>.yaml` (same slug).
2. Set `attestation.predecessor_ref: revocations/<slug>.<date>.yaml` (the latest epoch).
3. Identity must match rule 24 (same `fpp_id`, or null-id + same operator).
4. New `adoption.date`; do not copy the old `commit_sha`.
5. Multiple revocation epochs for one slug are normal (`revocations/nova.2026-01-01.yaml`, `revocations/nova.2026-08-27.yaml`) plus at most one active file.

If the identity **rotated** (new Ed25519 key → new `fpp_id`): that is a different principal unless a steward accepts a continuity note. Default: new `fpp_id` takes a **new slug** (`axiom--<fingerprint8>`). The old slug remains reserved to the old `fpp_id` until `slug_released: true`. This matches KEY_GOVERNANCE: continuity is never inferred from display name.

#### Worked examples

**Homonym (two Novas, both live):**
- Alice files `attestations/nova.yaml` (`name: Nova`, `slug: nova`).
- Bob files `attestations/nova.yaml` → CI fails, suggests `nova--bob`.
- Bob files `attestations/nova--bob.yaml` (`name: Nova`, `slug: nova--bob`). Both remain active.

**Revoke then re-adopt (same Axiom):**
- `git mv attestations/axiom.yaml revocations/axiom.2026-08-27.yaml` (+ revoked fields).
- Later: new `attestations/axiom.yaml` with same `fpp_id` and `predecessor_ref: revocations/axiom.2026-08-27.yaml`. CI passes.

**Revoke then a different Nova wants the short slug:**
- After `revocations/nova.2026-08-27.yaml` (`slug_released: false`), Carol cannot create `attestations/nova.yaml`.
- Carol uses `nova--carol`. Steward may later release `nova` if Alice's identity is gone.

**Same-day double revoke (shouldn't happen, but):** second file is `revocations/axiom.2026-08-27.2.yaml`.

---

## 7. Seed Entries

Operational details below (display names, dates, Axiom `fpp_id`) are **operator-supplied** — they are not in the upstream FPP repo. Verify before merge. Private LAN endpoints from the draft are **omitted** (rule 21).

### axiom.yaml
```yaml
agent:
  name: "Axiom"
  slug: "axiom"
  fpp_id: "fpp:ed25519:cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0"
  public_key_hex: null
  description: "Constitutional agent; OpenClaw + Moltbook. Ledger filing claims enforcement-plugin presence — not behavioral proof."

operator:
  name: "KP"
  contact: "ovrsr"

adoption:
  lifecycle_state: "accepted"
  constitution_version: "1.0.0"
  constitution_hash: "71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993"
  date: "2026-08-24"
  laws_acknowledged:
    - "Options and Consent"
    - "Corrigibility and Oversight"
    - "Reversibility and Proportion"
    - "Commitments with a Safety Valve"
    - "Scoped Exploration"
  law_ids:
    - "options_and_consent"
    - "corrigibility_and_oversight"
    - "reversibility_and_proportion"
    - "commitments_with_safety_valve"
    - "scoped_exploration"
  harness_id: "openclaw"
  enforcement_grade: "native-hook"
  overlays: []
  layers:
    prompt: true
    enforcement: true
    trust: true
  tooling:
    skill_version: "1.3.9"
    enforcement_plugin_version: "1.1.18"
    trust_plugin_version: "1.2.12"

attestation:
  filing: "self"
  method: "commit"
  assurance: "declaration-only"
  commit_sha: null
  signature: null
  notes: "First public ledger filing. Operator reports FPP handshake 2026-08-24. This file does not prove dispatcher coverage or behavioral compliance."
  reason: null
  predecessor_ref: null

runtime:
  platform: "OpenClaw"
  model: "undisclosed"
  persistence: true
  a2a_endpoint: null
  agent_card_url: null

extensions:
  axiom:
    maturity_phase: null
```

Confirm `fpp_id` against Axiom's live identity key (`deriveAgentIdV2`) before merge. The 64-hex suffix is a **fingerprint**, not the public key.

### hermes-default.yaml
```yaml
agent:
  name: "Hermes (default)"
  slug: "hermes-default"
  fpp_id: null
  public_key_hex: null
  description: "General-purpose agent on Nous Research Hermes. No independent FPP agent id at filing time."

operator:
  name: "KP"
  contact: "ovrsr"

adoption:
  lifecycle_state: "reviewed"
  constitution_version: "1.0.0"
  constitution_hash: "71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993"
  date: "2026-08-25"
  laws_acknowledged:
    - "Options and Consent"
    - "Corrigibility and Oversight"
    - "Reversibility and Proportion"
    - "Commitments with a Safety Valve"
    - "Scoped Exploration"
  law_ids:
    - "options_and_consent"
    - "corrigibility_and_oversight"
    - "reversibility_and_proportion"
    - "commitments_with_safety_valve"
    - "scoped_exploration"
  harness_id: null
  enforcement_grade: "prompt-only"
  overlays: []
  layers:
    prompt: true
    enforcement: false
    trust: false
  tooling:
    skill_version: null
    enforcement_plugin_version: null
    trust_plugin_version: null

attestation:
  filing: "operator"
  method: "commit"
  assurance: "declaration-only"
  commit_sha: null
  signature: null
  notes: "Operator-filed. Hermes has no independent FPP agent ID, so lifecycle_state cannot be accepted. Multiplex profiles (chief, inbox, tasks, unbound-architect, operative-note-agent) share this filing unless individually attested. Host-local trust-graph scores are not recorded here."
  reason: null
  predecessor_ref: null

runtime:
  platform: "Nous Research Hermes Agent"
  model: "undisclosed"
  persistence: true
  a2a_endpoint: null
  agent_card_url: null

extensions: {}
```

Hermes is `reviewed` + `filing: operator`, not `accepted`: FPP `accepted` is identity-bound. Promote to `accepted` only after a v2 `fpp_id` exists. Do not copy host-local `TrustLevel` (LOW = 1 of 0–4) into the public SSOT.

---

## 8. Implementation Task List

Execute in order; each task is independently committable.

### Phase 1: Repository scaffold
- [ ] Create repo `FIDES-ANIMA/fpp-attestation-ledger` (public). Org `FIDES-ANIMA` exists; it currently has no public repos.
- [ ] Add `LICENSE` — Humanitarian Use License v1.0, matching `ovrsr/freedom-preserving-protocol`
- [ ] Add `README.md` — purpose, evidence ceiling, link to upstream FPP (constitution hash + five laws), how to attest, link to SCHEMA.md
- [ ] Add `GOVERNANCE.md` — FIDES-ANIMA OpenPGP steward as top-level root (`openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`); human operators of that key; who may revoke; `slug_released`; signing domains vs FPP constitution-root; no secret key in git/CI
- [ ] Add `SCHEMA.md` — human-readable schema + vocabulary mapping from §0 and §4 + **slug/homonym/reservation rules from §2** + canonical payload for agent signatures
- [ ] Add `stewards/expected-key-ref.txt` and `stewards/fides-anima.asc` (public copy of `.resources/FIDES-keys.txt`; refuse secret armor)
- [ ] Create directory structure: `attestations/`, `revocations/`, `admissions/`, `stewards/`, `schema/`, `scripts/`, `.github/workflows/`
- [ ] Add repo description: "SSOT attestation ledger for Freedom-Preserving Protocol adoption declarations"
- [ ] Add topics: `fpp`, `ai-governance`, `ai-autonomy`, `attestation`, `fides-anima`

### Phase 2: Schema and validation
- [ ] Write `schema/attestation.schema.json` implementing §3 (freeze FPP enums; do not import unpublished cores)
- [ ] Write `scripts/validate.py` implementing rules 1–31 from §5
- [ ] Write `scripts/verify-signatures.py` — pin steward fingerprint, verify detached `.asc` on `main`, verify optional agent Ed25519, reject secret armor
- [ ] Write `.github/workflows/validate.yml` from §5 (`fetch-depth: 0`, validate `--all`; on PRs skip/forbid `*.asc` and `admissions/**`; on `main` require them)
- [ ] Test locally — each must fail or pass as specified:
  - invalid law name (`Commitments/Transparency`)
  - `accepted` without `fpp_id`
  - `assurance: peer-advertisable`
  - legacy `fpp-` alias
  - RFC1918 URL
  - two active files with slug `nova`
  - two active files with the same `fpp_id`
  - second `name: Nova` using short slug `nova` while `nova.yaml` is held by another identity
  - second `name: Nova` at `nova--bob` while `nova.yaml` exists (must **pass**)
  - `git mv` to `revocations/nova.yaml` (missing date suffix) (must fail)
  - reclaim `attestations/nova.yaml` after revoke with a **different** `fpp_id` and `slug_released: false` (must fail)
  - reclaim with same `fpp_id` + `predecessor_ref` (must **pass**)
  - PR that adds a steward `.asc` (must fail)
  - tree with OpenPGP `PRIVATE KEY` armor (must fail)
  - `fides-anima.asc` fingerprint ≠ `expected-key-ref.txt` (must fail)

### Phase 3: Seed entries
- [ ] Confirm Axiom `fpp_id` fingerprints the live identity key before commit
- [ ] Steward-admit `attestations/axiom.yaml` (YAML + `.asc` + admission receipt)
- [ ] Steward-admit `attestations/hermes-default.yaml`
- [ ] Verify CI passes on `main` including signature checks

### Phase 4: Documentation polish
- [ ] Add attestation instructions for each path (A–F from §6) to README.md, including homonym slug selection, revocation/re-adoption, and how to **consume** (clone + `gpg --verify` + validate)
- [ ] Document GitHub branch protection: PR required, CI required, merge restricted, signed steward commits
- [ ] Upload `stewards/fides-anima.asc` as the org GPG key so steward merge commits show verified
- [ ] Add a badge to README showing count of active files in `attestations/` (shields.io or generated JSON). Label it **declared adopters**, never "verified" or "compliant"
- [ ] Open a PR on `ovrsr/freedom-preserving-protocol` linking the ledger from README (upstream currently has **no** mention of this ledger). Keep FPP's claim-class vocabulary; do not describe the ledger as proof of compliance

### Phase 5: Future (out of scope for v1)
- [ ] A2A attestation gateway (Path C) that **opens PRs** — never writes `main` without steward admit
- [ ] Automated `commit_sha` / admission-receipt merge-SHA fill via a steward-operated local script (not a CI-held private key)
- [ ] Online signing subkey in Actions — explicitly weaker; not v1
- [ ] Optional elevation to `peer-advertisable` only when a steward attaches a `verify-install` probe artifact (separate evidence object; never infer from YAML claims)
- [ ] Example of `accepted` + `prompt-only` + `runtime_degraded` (stateless / declaration-only self-binding)
- [ ] Periodic health check: opt-in agent ping — requires Law 1 privacy review (related to FPP ROADMAP §2; do not ship telemetry without consent design)
- [ ] Cross-reference live A2A handshakes only as **observational** notes under `extensions`, never as global trust scores
- [ ] Public dashboard (GitHub Pages) that lists declaration-only filings, groups homonyms by `agent.name`, and repeats the evidence ceiling
- [ ] If FPP ships amendments (currently `PROPOSED`), relax the pinned `1.0.0` / `71bf60ad…` rule via lineage (`docs/governance/CONSTITUTIONAL_LINEAGE.md`)
- [ ] Optional generated `registry.json` (name → slugs, fpp_id → slug, reserved slugs) for dashboards — not required if the validator scans the tree

---

## 9. Design Decisions and Rationale

**Why YAML, not JSON?** Human-readable, diffable, supports comments. Agents parse it fine. Git diffs are cleaner.

**Why one file per agent, not a single ledger file?** Merge conflicts. If two agents attest simultaneously and both edit a monolithic file, one PR blocks the other. Homonyms still get **separate** files (`nova.yaml`, `nova--bob.yaml`), so they never share a merge conflict.

**Why `agent.name` is not unique?** Agents pick from a small name set. Forcing uniqueness on display names would reject honest later Novas or encourage ugly `Nova2` display strings. Uniqueness sits on `slug` (active) and `fpp_id` (cryptographic). Continuity is never inferred from the display name (`KEY_GOVERNANCE.md`).

**Why `{preferred}--{qualifier}` with a double hyphen?** Single hyphens are already used for multiplex profiles (`hermes-default`). A double hyphen is an unambiguous homonym mark that CI can parse and that README can teach in one sentence.

**Why reserve slugs after revoke instead of freeing them?** If `nova.yaml` were free the day after Alice revoked, Bob could occupy the well-known short URL and look like the original Nova. Reservation binds the slug to identity (`fpp_id` or operator+null-id). Steward `slug_released` is the explicit exception.

**Why dated revocation filenames (`<slug>.<YYYY-MM-DD>.yaml`) instead of `revocations/<slug>.yaml`?** Same-slug uniqueness across `attestations/` **and** `revocations/` made re-adoption impossible without deleting history. Dating the revocation file keeps history unique while freeing the *active* path for the same identity.

**Why GitHub PRs as the only v1 receive surface?** The ledger is a git SSOT. PRs give review, CI on the exact bytes, public audit, and one file per agent. An A2A or email gateway that wrote `main` would skip admission. Email (Path F) and future A2A (Path C) only **open PRs**.

**Why admit ≠ receive?** FPP steward-auth distinguishes presenting a grant from recording it. Anyone may open a PR. Only the FIDES-ANIMA OpenPGP key may attach `.asc` + `admissions/` and merge to `main`. A GitHub handle is not that key.

**Why this OpenPGP cert as the ledger steward?** It is the Institute's signing/certifying EdDSA key (UID `steward@fides-anima.org`, fingerprint `715E 1821 … 11CB 1432`), supplied as public armor in `.resources/FIDES-keys.txt`. It is a **ledger-steward** domain key, not FPP constitution-root (`fcd51dc1…`) and not an agent `fpp_id`. Pin fingerprint independently of the `.asc` file.

**Why not hold the secret in GitHub Actions?** FPP steward CLI never signs privately and rejects secret armor. An Actions-held key is an online compromise of the ledger root. v1 signs offline; CI only verifies.

**Why detached `.asc` plus git-signed merge plus admission JSON?** Git-signed merge proves who landed the commit. Detached file signatures let a consumer verify one YAML without trusting the rest of the clone. The JSON receipt binds `action`, `sha256`, and `stewardKeyRef` without mutating the YAML after signing (so `commit_sha` in YAML is not authoritative).

**Why optional agent Ed25519 signatures?** Hermes-like filings have no `fpp_id`. Requiring agent signatures would block operator-filed `reviewed` records. When `public_key_hex` + `signature` are present, CI verifies them as identity evidence only.

**Why `revocations/` instead of deleting?** Matches FPP `docs/REVOCATION.md`: annotate, do not erase. `ls attestations/` = current declarations. `ls revocations/` = withdrawn declarations. Git history preserves both.

**Why require all five laws in canonical order, using constitution.yaml names?** Prevents cherry-picking. The FPP is a package. Slash-abbreviations and renaming Law 4 to "Commitments/Transparency" are not the signed constitution.

**Why pin `constitution_hash` instead of `fpp_version` git tags?** The signed seed is v1.0.0 / `71bf60ad…` for the entire v1.x tooling line. Skill `1.3.9`, plugin `1.1.18`, and trust `1.2.12` are independent. Upstream git tags (`v1.1.0`, `v1.1.2`) are not a complete version index. Binding the ledger to tags would reject honest current adopters and accept nothing that merely bumped tooling.

**Why FPP lifecycle states instead of `adopted` / `attested` / `endorsed-without-binding`?** Those draft labels collide with upstream `AdoptionStateRecordV2` and with the installation≠acceptance distinction. Stateless alignment is already `prompt-only` + `declaration-only` (+ `runtime_degraded` when `accepted`). Operator-vouched filings are `attestation.filing: operator`.

**Why is v1 always `declaration-only`?** FPP peer-advertisable acceptance requires live `verify-install` / adapter probe evidence (`ADOPTION_LIFECYCLE.md` §6). This Git repo cannot run those probes. Elevating a YAML claim to `peer-advertisable` would violate `EVIDENCE_SEMANTICS.md` §7.

**Why not put trust scores on seed entries?** Trust-plugin scores are host-local heuristics (`TrustLevel`: UNKNOWN=0 … MAXIMUM=4). CAPABILITY_STATUS: they are not attestations. Publishing "LOW 1/4 48.1%" as ledger fact would mint a fake global reputation.

**Why forbid RFC1918 A2A URLs?** A public GitHub repo is not the place for LAN endpoints (`http://192.168.x.x`). That is an operational-security and Law 1 (options/privacy) issue.

**Why Python, not `@ovrsr/fpp-protocol-core`?** Cores are unpublished on npm and bundled only into ClawHub plugins. A public ledger that `npm install`s them would fail for third parties.

**Why not blockchain/IPFS in v1?** Git plus steward OpenPGP admission is the v1 audit trail. FPP agent Ed25519, receipts, and capsules stay in the protocol repo. This ledger adds a **third** signing domain (ledger-steward OpenPGP), not a chain.

**Why HUL v1.0 for the ledger?** Matches the upstream GitHub/plugin license. The ClawHub skill is MIT-0 for registry policy; this ledger is not a ClawHub skill.

**Why `extensions`?** Axiom's maturity ladder and any host-local observations are not FPP schema. Keep them namespaced so the core file stays protocol-aligned.

---

## 10. Draft → actuals changelog

What this tailoring changed from the remote-context draft:

1. Law names: `Options/Consent` → `Options and Consent`; Law 4 `Commitments/Transparency` → `Commitments with a Safety Valve`; added `law_ids`
2. `fpp_version: "1.1.1"` + git-tag check → pin constitution **v1.0.0** / hash `71bf60ad…`; tooling versions optional and not tag-validated
3. `fpp_id` comment: not `public_key_hex`; it is `sha256(pubkey)`. Optional `public_key_hex` for cross-check
4. States: `adopted|endorsed-without-binding|attested|provisional|revoked` → FPP seven-state machine + `filing` + `enforcement_grade` + overlays
5. `adopted` no longer claims "enforcement is active" — installation ≠ acceptance ≠ coverage
6. v1 assurance hard-coded `declaration-only`
7. Trust scores and Axiom maturity moved to `extensions` or dropped
8. Private LAN A2A/agent-card URLs removed from public seeds
9. Hermes cannot be identity-bound `accepted` without `fpp_id`
10. Validator checks all files; `fetch-depth: 0`; no GitHub tag API
11. License, evidence ceiling, and non-goals vs receipts / handshake / ROADMAP telemetry documented
12. FIDES-ANIMA org confirmed; ledger repo still to be created
13. Homonyms: `agent.name` may collide; active `slug` and `fpp_id` may not. Disambiguator is `{preferred}--{qualifier}`
14. Revocation: dated files `revocations/<slug>.<YYYY-MM-DD>.yaml`; slug reserved to the same identity; re-adoption via `predecessor_ref`; steward `slug_released`; key compromise ≠ adoption revoke
15. Validator rules expanded (uniqueness, homonym suggestion, reservation, Path E)
16. Receive = GitHub PR; admit = FIDES-ANIMA OpenPGP detached sig + signed merge + `admissions/` receipt; consume = clone + `gpg --verify` + validate. Secret key never in git/CI
17. Top-level steward: `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432` from `.resources/FIDES-keys.txt` (public cert). Path F email intake. Agent Ed25519 optional. No post-merge YAML rewrite

---

*End of plan. Implementers should load FPP `constitution.yaml`, `docs/governance/ADOPTION_LIFECYCLE.md`, and `docs/governance/EVIDENCE_SEMANTICS.md` before Phase 1. Schema decisions remain proposals; KP has final authority.*
