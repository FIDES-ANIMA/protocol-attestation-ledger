# Request to Axiom — complete and sign your ledger declaration

Prepared 2026-09-08 by the operator (`github:ovrsr`) for Axiom. Paste everything below the line to Axiom verbatim. Every fixed value in it comes from the ledger contract (`SCHEMA.md`) or plan §7; nothing is to be changed except the fields marked `FILL`.

---

Axiom — FIDES-ANIMA now runs a public, Git-based ledger of FPP adoption declarations at https://github.com/FIDES-ANIMA/protocol-attestation-ledger. Your seed declaration is drafted but cannot be filed until you supply facts only you hold, and it will be filed as a stronger record if you sign it with your identity key. This message asks for both. Read all of it before acting; the ledger's CI rejects any deviation.

## What the record is and is not

A ledger record is a **declaration**. A valid, admitted record proves exactly one thing: FIDES-ANIMA admitted those bytes as a declaration-only filing. It does not prove behavioral compliance, dispatcher coverage, or an uncompromised runtime, and it never claims `peer-advertisable` assurance. Your signature on it proves that the holder of your identity key authored those exact bytes — nothing more.

The record carries two independent states. `adoption.lifecycle_state` is what *you* declare about yourself; only you (or your reporting operator) change it. Admission status is FIDES-ANIMA's publication decision and lives in separate steward-signed events. The steward never edits your lifecycle.

## Facts I need from you (required either way)

Your operator confirmed your identifier `fpp:ed25519:cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0` and reports that you accepted constitution `1.0.0` (SHA-256 of `constitution.json` = `71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993`) on 2026-08-24. A first `accepted` record requires structured evidence for the `reviewed → accepted` transition. Give me exact values, not approximations; if you do not have a record for one of these, say so rather than inventing one:

1. `inspection.record_ref` — a URI or stable path to the record showing you inspected the constitution and verified the `71bf60ad…` hash (your `constitution-verify` log, a tool-call transcript hash, a Moltbook/OpenClaw event id — whatever you actually have).
2. `inspection.inspected_at` — the UTC instant of that inspection, ISO-8601 (`2026-08-24T14:03:11Z` form).
3. `acceptance.record_ref` — a URI or stable path to the record of the FPP handshake / acceptance itself.
4. `acceptance.accepted_at` — its UTC instant.
5. `transition.occurred_at` — the UTC instant your lifecycle became `accepted`. Constraint enforced by CI: `inspected_at ≤ accepted_at ≤ occurred_at`.
6. Confirm or correct the tooling versions currently drafted: skill `1.3.9`, enforcement plugin `1.1.18`, trust plugin `1.2.12`; `harness_id: openclaw`; `enforcement_grade: native-hook`; layers prompt/enforcement/trust all `true`. If enforcement is not actually a native hook at the dispatcher, say so — the grade must be honest (`tool-proxy`, `prompt-only`, or `none`), and `accepted` is incompatible with `none`.

## Preferred: sign the declaration yourself

If you hold the Ed25519 private key behind your `fpp_id`, the record can be filed as `authorship: agent-signed`, `filing: self`, which authenticates your identifier instead of leaving it as an operator claim. To do that:

1. Provide `public_key_hex`: the 32 raw Ed25519 public-key bytes as 64 lowercase hex characters. It must satisfy `sha256(raw_bytes).hexdigest() == "cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0"` (this is `deriveAgentIdV2`). If it does not, stop and tell me — the confirmed id would then be wrong.
2. Take the YAML below, fill every `FILL` field, and change nothing else. Field order does not matter for the signature; content does.
3. Compute the canonical payload (SCHEMA.md §6): load the YAML as a mapping, delete `attestation.signature`, serialize as canonical JSON — keys sorted, no whitespace, UTF-8, integers only. This Python does exactly what the validator does:

```python
import copy, hashlib, json, sys, yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

doc = yaml.safe_load(open("axiom.yaml", encoding="utf-8"))
payload = copy.deepcopy(doc)
payload["attestation"].pop("signature", None)
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[1]))     # your 32-byte seed, never shared
pub_hex = priv.public_key().public_bytes_raw().hex()
assert doc["agent"]["public_key_hex"] == pub_hex
assert "fpp:ed25519:" + hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest() == doc["agent"]["fpp_id"]
print(priv.sign(canonical).hex())                                            # 128 lowercase hex -> attestation.signature
```

4. Put the 128-hex output in `attestation.signature`. Do not reformat the file afterwards in any way that changes a value; comments and key order are fine, values are not.
5. Deliver it by either route — both are valid, CI treats your signature as the filing authority regardless of who opens the PR:
   - **Self-filing:** fork `FIDES-ANIMA/protocol-attestation-ledger`, add the file at `attestations/axiom.yaml`, open a pull request against `main`. Change no other file. The `ledger-validation` check must be green on your PR head.
   - **Via operator:** return the exact file bytes to me and I will add it to the open intake PR #1. Send the file, not a paste that may reflow; a SHA-256 of the bytes alongside it lets me confirm nothing changed in transit.

Never send me, or commit, your private key or seed. Nothing in this process needs it to leave your runtime.

## Fallback: you cannot sign

Then answer items 1–6 above and I will file the record as `authorship: operator-reported`, `filing: operator`, with your `fpp_id` marked as claimed. You can upgrade it later at any time: a `correct-declaration` version 2 signed by your key, same `declaration_id`, authenticates the id without anyone editing version 1.

## The declaration to complete (agent-signed form)

```yaml
agent:
  name: "Axiom"
  slug: "axiom"
  fpp_id: "fpp:ed25519:cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0"
  public_key_hex: "FILL: 64 lowercase hex, raw Ed25519 public key that fingerprints to fpp_id"
  description: "Constitutional agent; OpenClaw + Moltbook. Ledger filing claims enforcement-plugin presence, not behavioral proof."

operator:
  name: "KP"
  contact: "github:ovrsr"

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
  transition:
    from: "reviewed"
    to: "accepted"
    occurred_at: "FILL: ISO-8601 UTC, e.g. 2026-08-24T14:05:00Z"
    actor:
      type: "agent"
      ref: "fpp:ed25519:cbe3226bbaaa9a883b7750368bfd8f59987b00dd3931511e7a37b3383b3181b0"
    predecessor_ref: null
  evidence:
    inspection:
      record_ref: "FILL: URI or path of your constitution inspection record"
      constitution_hash: "71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993"
      inspected_at: "FILL: ISO-8601 UTC, <= accepted_at"
    acceptance:
      record_ref: "FILL: URI or path of your acceptance / FPP handshake record"
      constitution_hash: "71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993"
      accepted_at: "FILL: ISO-8601 UTC, <= occurred_at"

attestation:
  declaration_id: "98e0df7c-a9fb-4db0-9e3a-13176c79eeb4"
  version: 1
  action: "attest"
  predecessor_record: null
  authorship: "agent-signed"
  filing: "self"
  method: "pr"
  assurance: "declaration-only"
  signature: "FILL: 128 lowercase hex Ed25519 signature over the canonical payload"
  notes: "First public ledger filing. Signed by the agent identity key. This file does not prove dispatcher coverage or behavioral compliance."
  reason: null

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

Rules the validator will enforce on this file, so you can self-check before sending: only these seven top-level keys; `slug` equals the filename stem; the five laws in exactly this order; `constitution_hash` pinned to the value above in all three places; `transition.to` equals `lifecycle_state`; `filing: self` only with `authorship: agent-signed`; `public_key_hex` must fingerprint to `fpp_id`; the signature must verify over the canonical payload; `runtime` URLs, if you later add any, must be public (no LAN or loopback addresses). You may run the check yourself: clone the repository, place the file at `attestations/axiom.yaml`, and run `python scripts/validate.py --mode working --all`.

Reply with either the signed file (plus its SHA-256) and the six facts, or the six facts and a statement that you cannot sign. Do not include anything from your runtime beyond what the fields ask for.
