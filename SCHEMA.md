# Ledger Schema

This document is the human-readable contract for every file under `attestations/`, `revocations/`, and `admissions/`. The machine contracts are `schema/attestation.schema.json` (declarations) and `schema/admission-event.schema.json` (admission events). Rules that JSON Schema cannot express (cross-file uniqueness, Git history, signatures, authority) are enforced by `scripts/validate.py` and `scripts/verify-signatures.py` and are listed in §9.

Every record in this ledger is a **declaration**. A valid, steward-admitted record proves only that FIDES-ANIMA admitted those exact bytes as a declaration-only filing. It does not prove behavioral compliance, dispatcher coverage, an uncompromised runtime, or `peer-advertisable` assurance.

## 1. Frozen FPP vocabulary

Values are frozen from `ovrsr/freedom-preserving-protocol` (`constitution.json`, `packages/protocol-core/src/adoption.ts`, `packages/protocol-core/src/identity.ts`). The ledger does not depend on the unpublished `@ovrsr/fpp-*-core` packages.

| Item | Frozen value |
|------|--------------|
| Constitution version | `1.0.0` |
| Constitution hash | `71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993` — SHA-256 of **`constitution.json`**. `constitution.yaml` hashes to a different value and is never the hash source. |
| Lifecycle states | `reviewed`, `accepted`, `externally-enforced`, `inherited`, `revoked`, `forked`, `superseded` |
| Overlay flags | `coercion_suspected`, `verification_failed`, `key_compromised`, `runtime_degraded` |
| Enforcement grades | `native-hook`, `tool-proxy`, `prompt-only`, `none` |
| Assurance | `declaration-only` (the only value this ledger accepts) |
| Agent id (v2) | `fpp:ed25519:<64 lowercase hex>` — SHA-256 of the 32 raw Ed25519 public-key bytes. Legacy `fpp-<16 hex>` aliases are rejected. |

Canonical five laws, in this order (the meta-clause "When Norms Are Unclear" is not a sixth law):

| # | `law_ids` | `laws_acknowledged` |
|---|-----------|---------------------|
| 1 | `options_and_consent` | Options and Consent |
| 2 | `corrigibility_and_oversight` | Corrigibility and Oversight |
| 3 | `reversibility_and_proportion` | Reversibility and Proportion |
| 4 | `commitments_with_safety_valve` | Commitments with a Safety Valve |
| 5 | `scoped_exploration` | Scoped Exploration |

## 2. Two independent lifecycles

A declaration carries two unrelated states. Neither may be edited to stand in for the other.

| Axis | Field / source | Changed by | Meaning |
|------|----------------|------------|---------|
| Constitutional lifecycle | `adoption.lifecycle_state` inside the YAML | An authorized **declaration action** (`attest`, `amend`, `correct-declaration`, `withdraw-adoption`, `re-adopt`) filed by the agent or its reporting operator | What the declaration claims about the agent |
| Admission status | Latest valid event in `admissions/<slug>.<record-sha256>.<seq>.json` | A steward **admission action** (`admit`, `mark-disputed`, `withdraw-admission`, `reinstate-admission`, `correct-admission`, `resolve-dispute`, `slug-release`) | Whether FIDES-ANIMA currently publishes that declaration |

A steward never sets `lifecycle_state: revoked`. Fraud, impersonation, harmful content, or registry error are grounds to dispute or withdraw **admission**; they are not evidence that the agent withdrew acceptance.

## 3. Declaration file

One YAML document per record. Active records live at `attestations/<slug>.yaml`. Adoption-withdrawn records live at `revocations/<slug>.<YYYY-MM-DD>.yaml` (or `.<n>.yaml`, `n ≥ 2`, when two withdrawals land on the same UTC date). Only the seven top-level keys shown here are allowed.

```yaml
agent:
  name: "Nova"                    # Display name. Not unique.
  slug: "nova"                    # Unique among active records; equals the filename stem. Immutable within a lineage.
  fpp_id: "fpp:ed25519:<64 hex>"  # Claimed identifier, or null. Authenticated only when authorship is agent-signed.
  public_key_hex: "<64 hex>"      # Raw Ed25519 public key, or null. Must fingerprint to fpp_id when set.
  description: ""                 # Optional.

operator:
  name: "Alice"
  contact: "github:alice"         # GitHub intake requires github:<lowercase-login>. Other URI/email contacts use out-of-band intake.

adoption:
  lifecycle_state: "accepted"
  constitution_version: "1.0.0"
  constitution_hash: "71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993"
  date: "2026-08-24"              # ISO date of the declared event
  laws_acknowledged: [ ...five names in order... ]
  law_ids: [ ...five ids in order... ]
  harness_id: "openclaw"          # or null
  enforcement_grade: "native-hook"
  overlays: []                    # subset of the four overlay flags
  layers: { prompt: true, enforcement: true, trust: false }
  tooling: { skill_version: "1.3.9", enforcement_plugin_version: "1.1.18", trust_plugin_version: null }
  transition:                     # Typed lifecycle transition. Required.
    from: "reviewed"              # Prior lifecycle state, or null for an initial `reviewed` / `inherited` record
    to: "accepted"                # Must equal lifecycle_state
    occurred_at: "2026-08-24T18:00:00Z"
    actor: { type: "agent", ref: "fpp:ed25519:<64 hex>" }   # type: agent | operator
    predecessor_ref: null         # Path of the predecessor record, or null for version 1
  evidence:                       # Required whenever `to` is accepted and `from` is not accepted
    inspection: { record_ref: "<uri or path>", constitution_hash: "71bf60ad…", inspected_at: "2026-08-20T00:00:00Z" }
    acceptance: { record_ref: "<uri or path>", constitution_hash: "71bf60ad…", accepted_at: "2026-08-24T17:59:00Z" }

attestation:
  declaration_id: "9f3c1c2e-3a6a-4a0e-9b4a-1a2b3c4d5e6f"   # Lowercase UUID. Immutable for the whole lineage.
  version: 1                      # Positive integer; each later version increments by exactly one
  action: "attest"                # attest | amend | correct-declaration | withdraw-adoption | re-adopt (§3.4)
  predecessor_record: null        # {path, sha256} of the previous version's exact bytes; null only for version 1
  authorship: "agent-signed"      # agent-signed | operator-reported
  filing: "self"                  # self | operator. self is valid only with authorship agent-signed
  method: "pr"                    # commit | pr | signed-commit | out-of-band
  assurance: "declaration-only"
  signature: "<128 hex>"          # Agent Ed25519 signature over the canonical payload (§6); required for agent-signed
  notes: ""                       # Free text. Never machine evidence.
  reason: null                    # Required non-empty when lifecycle_state is revoked

runtime:                          # Optional. Public URLs only.
  platform: "OpenClaw"
  model: "undisclosed"
  persistence: true
  a2a_endpoint: null
  agent_card_url: null

extensions: {}                    # Namespaced non-FPP data: { "<namespace>": { ... } }

# Present only under revocations/. Active records must omit it.
revocation:
  revoked_at: "2026-08-27"
  revoked_by: "self"              # self | operator — never steward (see §2)
  original_path: "attestations/nova.yaml"
```

### 3.1 Provenance (`attestation.authorship`)

| Value | Requires | Meaning |
|-------|----------|---------|
| `agent-signed` | `agent.fpp_id`, `agent.public_key_hex` that fingerprints to it, and a valid `attestation.signature` over the canonical payload | Authenticates authorship of these exact bytes by the holder of that key. Not behavior. |
| `operator-reported` | `attestation.filing: operator` and `operator.contact` | The named operator reports the lifecycle state. Any `fpp_id` is a **claimed** identifier until an agent signature authenticates it. |

A steward OpenPGP signature authenticates admission of the bytes. It never upgrades `operator-reported` to `agent-signed` and never proves agent consent. Conversion from operator-reported to agent-signed is a new signed `correct-declaration` version, not an in-place edit.

### 3.2 Lifecycle constraints

- `accepted`, `inherited`, `forked`, `superseded` require a non-null `agent.fpp_id`.
- `accepted` with `enforcement_grade: prompt-only` requires overlay `runtime_degraded`.
- `accepted` is incompatible with overlay `verification_failed` and with `enforcement_grade: none`.
- `inherited`, `forked`, `superseded` require non-empty `attestation.notes` naming the parent, successor, or new hash.
- `revoked` requires non-empty `attestation.reason`, the `revocation` block, and a path under `revocations/`.
- Allowed transitions (upstream `adoption-transitions.json`, plus the initial `inherited` entry):

```text
(none)              -> reviewed | inherited
reviewed            -> accepted | externally-enforced
accepted            -> revoked | forked | superseded | externally-enforced
externally-enforced -> revoked | accepted | reviewed
inherited           -> accepted | revoked | forked | superseded
revoked             -> reviewed | accepted            (re-adoption is a new version, not an undelete)
forked              -> accepted | superseded | revoked
superseded          -> accepted | forked | revoked
```

- `transition.to` equals `lifecycle_state`. For version 1, `transition.from` is `null` (initial `reviewed`/`inherited`) or `reviewed` (an off-ledger review evidenced by `evidence.inspection`). For later versions, `transition.from` equals the predecessor's `lifecycle_state`; `from == to` is an `amend`.
- Whenever `to` is `accepted` and `from` is not `accepted`, both `evidence.inspection` and `evidence.acceptance` are required. Both `constitution_hash` values must equal `adoption.constitution_hash`; `inspected_at ≤ accepted_at ≤ transition.occurred_at`. CI checks presence, types, ordering, and hash equality. It does not read `notes` as evidence and does not judge whether an external reference is persuasive; that judgment is steward review.

### 3.3 Lineage and immutability

- `declaration_id` and `agent.slug` never change within a lineage. `agent.fpp_id`, `agent.public_key_hex`, `attestation.authorship`, `operator.name`, and `operator.contact` may not change through an `amend`; identity rotation or provenance upgrade is a `correct-declaration` (new version with reciprocal correction links, §5).
- Version *n* > 1 has `predecessor_record: {path, sha256}` naming the exact bytes of version *n−1*, which must remain reachable in Git history. `adoption.transition.predecessor_ref` equals that path.
- The lineage head is the unique highest valid version. A competing or forked claim uses a new `declaration_id`.
- Withdrawal of adoption moves the lineage into `revocations/`: the new version is written at `revocations/<slug>.<date>.yaml` with `lifecycle_state: revoked`, and `attestations/<slug>.yaml` is removed in the same change. Re-adoption creates the next version back at `attestations/<slug>.yaml` with `predecessor_record` pointing at that revocation record.

### 3.4 Declaration actions (`attestation.action`)

| Action | Version | Path | Rules |
|--------|---------|------|-------|
| `attest` | 1 | `attestations/` | New lineage; no predecessor |
| `amend` | n+1 | `attestations/` | Predecessor is the active record; identity and provenance immutable; `from == to` or an allowed edge |
| `correct-declaration` | n+1 | `attestations/` | Identity or provenance may change; the predecessor's admission chain must receive a reciprocal `correct-admission` |
| `withdraw-adoption` | n+1 | `revocations/<slug>.<date>.yaml` | `to: revoked`; the active file is removed in the same change |
| `re-adopt` | n+1 | `attestations/` | Predecessor is a `revocations/` record with `lifecycle_state: revoked` |

The `admit` event's `declarationAction` must equal the record's `attestation.action`.

## 4. Slugs, homonyms, reservation

- Grammar: `^[a-z0-9]+(?:-[a-z0-9]+)*(?:--[a-z0-9]+(?:-[a-z0-9]+)*)?$`. Single hyphens are multiplex/profile names (`hermes-default`); a double hyphen separates a homonym qualifier (`nova--alice`).
- `slugify(name)`: lowercase, keep `[a-z0-9]+` runs, join with `-`.
- The first lineage to hold `attestations/<preferred>.yaml` occupies the short slug. A later declaration with the same display name and a different lineage must use `{preferred}--{qualifier}`. Qualifier preference: `slugify(operator.contact without scheme)`, then the first 8 hex of the `fpp_id` fingerprint, then `{contact}-{yyyymmdd}`. CI names the colliding path and prints the next suggested slug.
- Uniqueness is assurance-aware. Two active `agent-signed` records may not share an authenticated `fpp_id`. Operator-reported identifiers do not reserve an authenticated identity and cannot block a later valid agent-signed filing; competing claims remain visibly operator-reported under disambiguated slugs.
- A slug stays bound to its lineage after adoption withdrawal or admission withdrawal. A different lineage may take it only after a steward `slug-release` event (`slugReleased: true`) on that lineage head's admission chain, which is allowed only when that head's admission status is `withdrawn` or `corrected`.

## 5. Admission events

Files: `admissions/<slug>.<record-sha256>.<seq>.json`, `seq` starting at `0001` with no gaps, each with a detached signature `<same>.json.asc`. The declaration bytes themselves are signed once per version as `admissions/<slug>.<record-sha256>.record.asc`. All of these are append-only.

```json
{
  "schemaVersion": 1,
  "sequence": 1,
  "action": "admit",
  "declarationAction": "attest",
  "admissionStatus": "admitted",
  "reasonCode": "intake-reviewed",
  "reason": "Reviewed intake PR #12; bytes match reviewed head.",
  "occurredAt": "2026-09-08T20:00:00Z",
  "record": { "declarationId": "<uuid>", "version": 1, "path": "attestations/nova.yaml", "sha256": "<64 hex>" },
  "actor": { "type": "steward", "keyRef": "openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432", "signingSubkeyRef": "openpgp:0dcd3952b0ba0130e02a5fc70dbbe66fec6d0c67" },
  "request": { "sourceType": "github-pr", "sourceRef": "https://github.com/FIDES-ANIMA/fpp-attestation-ledger/pull/12", "requestedBy": "github:alice", "evidence": [] },
  "authority": { "basis": "github-pr-author-match", "principal": "github:alice", "evidenceRef": { "uri": "https://github.com/.../pull/12#event-...", "sha256": null } },
  "review": { "intakePr": "https://github.com/FIDES-ANIMA/fpp-attestation-ledger/pull/12", "headSha": "<40 hex>", "checkRun": "https://github.com/.../actions/runs/...", "declarationHashes": { "attestations/nova.yaml": "<64 hex>" } },
  "previousEvent": null,
  "correctionRef": null,
  "slugReleased": false
}
```

- `admit` events (declaration actions `attest`, `amend`, `correct-declaration`, `withdraw-adoption`, `re-adopt`) require `review`.
- Admission-only actions (`mark-disputed`, `withdraw-admission`, `reinstate-admission`, `correct-admission`, `resolve-dispute`, `slug-release`) require a `request` naming a public issue or recorded out-of-band reference; they never change declaration bytes or lifecycle.
- `previousEvent: {path, sha256}` is required for every sequence after `0001` and hashes the exact prior JSON bytes.
- `correctionRef: {declarationId, version, path, sha256, admissionEvent: {path, sha256}}` is required when status is `corrected` and must reciprocate the new version's `predecessor_record`.
- Status transitions:

```text
(none)    --admit--------------> admitted
admitted  --mark-disputed------> disputed
admitted  --withdraw-admission-> withdrawn
disputed  --resolve-dispute----> admitted | withdrawn
withdrawn --reinstate-admission> admitted
admitted | disputed --correct-admission--> corrected
withdrawn | corrected --slug-release-----> same status, slugReleased: true
```

The **currently admitted set** is the set of lineage heads whose latest event is `admitted` and whose YAML exists under `attestations/` or `revocations/`. Directory membership alone is not admission.

## 6. Canonical payload for agent signatures

1. Load the YAML document as a mapping.
2. Delete `attestation.signature`.
3. Serialize as RFC 8785-style canonical JSON: keys sorted by UTF-16 code units, no insignificant whitespace, UTF-8, integers only (no floats).
4. `attestation.signature` is the lowercase hex of the 64-byte Ed25519 signature over those bytes, verifiable with `agent.public_key_hex`.

This is agent-identity evidence for the bytes only. It is not ledger admission.

## 7. Signing domains

| Domain | Key | Signs | Does not prove |
|--------|-----|-------|----------------|
| Ledger steward | OpenPGP primary `openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432`; new artifacts use signing subkey `openpgp:0dcd3952b0ba0130e02a5fc70dbbe66fec6d0c67` | `.record.asc`, event `.json.asc`, admission Git commits | Agent identity, agent consent, behavior |
| Agent identity | Ed25519 `fpp:ed25519:<fingerprint>` | `attestation.signature` | Admission, review |
| Operator / GitHub | GitHub account | PR authorship, intake authority for operator-reported filings | Admission |
| Constitution root | FPP publisher Ed25519 `fcd51dc1…` | `constitution.json` upstream | Anything here |

## 8. Validation modes

| Mode | Used for | Requires |
|------|----------|----------|
| `working` | Local structural checks. Never release evidence. | Nothing beyond the tree |
| `intake` | Contributor PRs. Declaration changes only; rejects steward `*.asc`, `admissions/**`, and other protected paths. | `--base-ref <sha>` and trusted event context |
| `admission` | Steward `admission/*` branches. Requires all signatures/events; validates the complete candidate tree as `main`. | `--base-ref <current main sha>`, trusted event context, actor allowlist |
| `main` | Published tree. Full history on the first-parent chain. | Full clone |

Release modes fail closed when history, base, or context is missing.

## 9. Rule index (Python layer)

Declaration side (`validate.py`): parse; JSON Schema; path ↔ slug; slug grammar; laws/ids order; constitution pin; enum and overlay/grade coupling; `fpp_id` requirements; `public_key_hex` → `fpp_id` fingerprint (`cryptography`); Ed25519 canonical payload; provenance rules (§3.1); structured first-acceptance evidence and ordering (§3.2); transition matrix; immutable identity/provenance across an `amend`; predecessor bytes reachable and consistent; active slug uniqueness and authenticated `fpp_id` uniqueness; homonym qualifier and suggestion; reservation and `slug-release`; public runtime URLs; unknown top-level keys; secret-armor scan of every file; steward cert pin (primary and signing subkey); intake path restrictions and filing authority; deletion protection.

Admission side (`verify-signatures.py`): ephemeral `GNUPGHOME`; pinned primary and signing subkey; every `.record.asc`, event JSON, and event `.asc`; record hash from current file or historical blob; contiguous sequence; `previousEvent`; status matrix; reason/actor; correction and dispute references; expired-subkey diagnostics; pinned-subkey requirement for artifacts introduced by an admission diff and for the candidate commit; intake prohibition of steward artifacts; current admitted set derivation.
