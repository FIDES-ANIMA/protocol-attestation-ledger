"""Declaration-side contract for scripts/validate.py.

Case numbers refer to docs/plans/2026-08-30-fpp-attestation-ledger-v1-staged.md §D2.
"""

from __future__ import annotations

import copy

import pytest
import yaml

from .conftest import (
    CONSTITUTION_HASH,
    PRIVATE_ARMOR,
    STEWARD_LOGIN,
    AgentKey,
    Ledger,
    assert_fails,
    assert_passes,
    declaration,
    output,
    revocation_of,
    successor,
)

NOVA = "attestations/nova.yaml"


def intake(ledger: Ledger, base: str, **ctx: object) -> tuple[str, object]:
    head = ledger.commit("intake change")
    ctx.setdefault("head_ref", "intake/alice/nova")
    ctx.setdefault("head_repo", "FIDES-ANIMA/fpp-attestation-ledger")
    path = ledger.context(head_sha=head, base_sha=base, **ctx)  # type: ignore[arg-type]
    return head, ledger.validate("intake", base_ref=base, context=path)


# --------------------------------------------------------------------------- sanity


def test_empty_tree_passes_in_working_mode(ledger: Ledger) -> None:
    assert_passes(ledger.validate())


def test_valid_reviewed_and_accepted_records_pass(ledger: Ledger) -> None:
    key = AgentKey()
    ledger.write_yaml(NOVA, declaration())
    ledger.write_yaml("attestations/axiom.yaml", declaration(name="Axiom", state="accepted", key=key,
                                                           grade="native-hook"))
    assert_passes(ledger.validate())


def test_summary_counts_admitted_heads_by_provenance_only(ledger: Ledger) -> None:
    """Working mode has no admissions, so the summary must report zero admitted heads."""
    ledger.write_yaml(NOVA, declaration())
    result = ledger.validate(extra=["--summary"])
    assert_passes(result)
    text = output(result)
    assert "currently admitted declarations" in text
    assert "agent-signed" in text and "operator-reported" in text
    assert "declared adopters" not in text and "verified" not in text.lower()


# --------------------------------------------------------------------------- cases 1-5 (schema/vocabulary)


def test_case01_invalid_law_name_fails(ledger: Ledger) -> None:
    doc = declaration()
    doc["adoption"]["laws_acknowledged"][3] = "Commitments/Transparency"
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "laws_acknowledged")


def test_case01b_law_ids_out_of_order_fails(ledger: Ledger) -> None:
    doc = declaration()
    doc["adoption"]["law_ids"].reverse()
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA)


def test_case02_accepted_without_fpp_id_fails(ledger: Ledger) -> None:
    doc = declaration(state="accepted", fpp_id=None)
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "fpp_id")


def test_case03_peer_advertisable_fails(ledger: Ledger) -> None:
    doc = declaration()
    doc["attestation"]["assurance"] = "peer-advertisable"
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "assurance")


def test_case04_legacy_alias_fails(ledger: Ledger) -> None:
    doc = declaration(state="accepted", fpp_id="fpp-cbe3226bbaaa9a88")
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "fpp_id")


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.5:8080/a2a",
        "https://10.0.0.7/agent.json",
        "http://172.16.4.4/",
        "http://localhost:3000/agent",
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://[fe80::1]/",
    ],
)
def test_case05_private_runtime_url_fails(ledger: Ledger, url: str) -> None:
    doc = declaration(runtime={"platform": "X", "model": "undisclosed", "persistence": True,
                               "a2a_endpoint": url, "agent_card_url": None})
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "runtime")


def test_public_runtime_url_passes(ledger: Ledger) -> None:
    doc = declaration(runtime={"platform": "X", "model": "undisclosed", "persistence": True,
                               "a2a_endpoint": "https://agents.example.org/nova/a2a", "agent_card_url": None})
    ledger.write_yaml(NOVA, doc)
    assert_passes(ledger.validate())


def test_constitution_hash_and_version_are_pinned(ledger: Ledger) -> None:
    doc = declaration()
    doc["adoption"]["constitution_hash"] = "da58a4f3b252bc1727e93876ed0c9e564e3312f049112abddf8519c6f8928058"
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "constitution_hash")
    doc = declaration()
    doc["adoption"]["constitution_version"] = "1.1.0"
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "constitution_version")


def test_unknown_top_level_key_fails(ledger: Ledger) -> None:
    doc = declaration()
    doc["trust_score"] = 0.48
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA)


def test_slug_must_match_filename_stem(ledger: Ledger) -> None:
    ledger.write_yaml("attestations/nova.yaml", declaration(slug="nova-prime"))
    assert_fails(ledger.validate(), "attestations/nova.yaml", "slug")


def test_overlay_and_grade_coupling(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(state="accepted", key=key, grade="prompt-only", overlays=[])
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "runtime_degraded")
    doc = declaration(state="accepted", key=key, grade="native-hook", overlays=["verification_failed"])
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "verification_failed")
    doc = declaration(state="accepted", key=key, grade="none", overlays=[])
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "none")


# --------------------------------------------------------------------------- cases 6-9 (uniqueness, homonyms)


def test_case06_two_active_files_with_same_slug_fail_naming_colliding_path(ledger: Ledger) -> None:
    ledger.write_yaml("attestations/nova.yaml", declaration(contact="github:alice"))
    ledger.write_yaml("attestations/nova-2.yaml", declaration(slug="nova", contact="github:bob"))
    assert_fails(ledger.validate(), "attestations/nova.yaml", "attestations/nova-2.yaml")


def test_case07_two_agent_signed_records_with_same_fpp_id_fail(ledger: Ledger) -> None:
    key = AgentKey()
    ledger.write_yaml("attestations/nova.yaml", declaration(key=key, contact="github:alice"))
    ledger.write_yaml("attestations/nova--bob.yaml", declaration(slug="nova--bob", key=key, contact="github:bob"))
    assert_fails(ledger.validate(), "attestations/nova.yaml", "attestations/nova--bob.yaml", "fpp_id")


def test_case08_homonym_without_double_hyphen_qualifier_fails_with_suggestion(ledger: Ledger) -> None:
    ledger.write_yaml("attestations/nova.yaml", declaration(contact="github:alice"))
    ledger.write_yaml("attestations/nova-bob.yaml", declaration(slug="nova-bob", contact="github:bob"))
    assert_fails(ledger.validate(), "attestations/nova.yaml", "nova--bob")


def test_case08b_intake_replacing_short_slug_holder_fails_with_suggestion(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration(contact="github:alice"))
    base = git_ledger.commit("alice holds nova")
    git_ledger.write_yaml(NOVA, declaration(contact="github:bob"))
    _, result = intake(git_ledger, base, actor="bob", head_ref="intake/bob/nova")
    assert_fails(result, "attestations/nova.yaml", "nova--bob")


def test_case09_homonym_with_qualifier_passes(ledger: Ledger) -> None:
    ledger.write_yaml("attestations/nova.yaml", declaration(contact="github:alice"))
    ledger.write_yaml("attestations/nova--bob.yaml", declaration(slug="nova--bob", contact="github:bob"))
    assert_passes(ledger.validate())


def test_homonym_suggestion_falls_back_to_fingerprint_when_contact_slug_taken(ledger: Ledger) -> None:
    key = AgentKey()
    ledger.write_yaml("attestations/nova.yaml", declaration(contact="github:alice"))
    ledger.write_yaml("attestations/nova--bob.yaml", declaration(slug="nova--bob", contact="github:bob"))
    ledger.write_yaml("attestations/nova-x.yaml", declaration(slug="nova-x", contact="github:bob", key=key))
    assert_fails(ledger.validate(), "attestations/nova-x.yaml", "nova--" + key.fpp_id.split(":")[2][:8])


def test_slug_grammar(ledger: Ledger) -> None:
    ledger.write_yaml("attestations/Nova.yaml", declaration(slug="Nova"))
    assert_fails(ledger.validate(), "slug")


# --------------------------------------------------------------------------- cases 10-12 (withdrawal, reservation)


def test_case10_revocation_without_date_suffix_fails(ledger: Ledger) -> None:
    key = AgentKey()
    active = declaration(key=key, state="accepted", grade="native-hook")
    active_bytes = ledger.write_yaml(NOVA, active)
    ledger.remove(NOVA)
    ledger.write_yaml("revocations/nova.yaml", revocation_of(active, NOVA, active_bytes, key=key))
    assert_fails(ledger.validate(), "revocations/nova.yaml")


def test_case11_reclaim_by_different_identity_fails(ledger: Ledger) -> None:
    alice, bob = AgentKey(), AgentKey()
    active = declaration(key=alice, state="accepted", grade="native-hook")
    active_bytes = ledger.write_yaml(NOVA, active)
    ledger.remove(NOVA)
    ledger.write_yaml("revocations/nova.2026-09-01.yaml", revocation_of(active, NOVA, active_bytes, key=alice))
    ledger.write_yaml(NOVA, declaration(key=bob, contact="github:bob"))
    assert_fails(ledger.validate(), NOVA, "revocations/nova.2026-09-01.yaml", "slug-release")


def test_case12_reclaim_same_lineage_with_predecessor_passes(ledger: Ledger) -> None:
    alice = AgentKey()
    active = declaration(key=alice, state="accepted", grade="native-hook")
    active_bytes = ledger.write_yaml(NOVA, active)
    ledger.remove(NOVA)
    revoked = revocation_of(active, NOVA, active_bytes, key=alice)
    rev_path = "revocations/nova.2026-09-01.yaml"
    rev_bytes = ledger.write_yaml(rev_path, revoked)
    readopt = successor(revoked, rev_path, rev_bytes, state="reviewed", key=alice, occurred_at="2026-09-05T00:00:00Z")
    ledger.write_yaml(NOVA, readopt)
    assert_passes(ledger.validate())


def test_readopt_without_predecessor_record_fails(ledger: Ledger) -> None:
    alice = AgentKey()
    active = declaration(key=alice, state="accepted", grade="native-hook")
    active_bytes = ledger.write_yaml(NOVA, active)
    ledger.remove(NOVA)
    ledger.write_yaml("revocations/nova.2026-09-01.yaml", revocation_of(active, NOVA, active_bytes, key=alice))
    same_lineage_v1 = declaration(key=alice, declaration_id=active["attestation"]["declaration_id"])
    ledger.write_yaml(NOVA, same_lineage_v1)
    assert_fails(ledger.validate(), NOVA)


def test_revocation_by_steward_is_not_a_declaration_action(ledger: Ledger) -> None:
    active = declaration()
    active_bytes = ledger.write_yaml(NOVA, active)
    ledger.remove(NOVA)
    ledger.write_yaml("revocations/nova.2026-09-01.yaml",
                      revocation_of(active, NOVA, active_bytes, revoked_by="steward"))
    assert_fails(ledger.validate(), "revocations/nova.2026-09-01.yaml", "revoked_by")


def test_revoked_record_requires_reason_and_block(ledger: Ledger) -> None:
    active = declaration()
    active_bytes = ledger.write_yaml(NOVA, active)
    ledger.remove(NOVA)
    doc = revocation_of(active, NOVA, active_bytes, reason="")
    ledger.write_yaml("revocations/nova.2026-09-01.yaml", doc)
    assert_fails(ledger.validate(), "reason")
    doc = revocation_of(active, NOVA, active_bytes)
    del doc["revocation"]
    ledger.write_yaml("revocations/nova.2026-09-01.yaml", doc)
    assert_fails(ledger.validate(), "revocation")


def test_active_record_must_not_carry_revocation_block(ledger: Ledger) -> None:
    doc = declaration()
    doc["revocation"] = {"revoked_at": "2026-09-01", "revoked_by": "self", "original_path": NOVA}
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "revocation")


# --------------------------------------------------------------------------- cases 14-15 (secret armor, pins)


def test_case14_secret_armor_anywhere_in_tree_fails(ledger: Ledger) -> None:
    ledger.write_yaml(NOVA, declaration())
    ledger.write("stewards/backup.txt", PRIVATE_ARMOR)
    assert_fails(ledger.validate(), "stewards/backup.txt")


def test_case14b_prose_mentioning_private_keys_is_not_armor(ledger: Ledger) -> None:
    ledger.write("GOVERNANCE.md", "The PRIVATE KEY and SECRET KEY never enter git.\n")
    assert_passes(ledger.validate())


def test_case15_cert_primary_fingerprint_mismatch_fails(ledger: Ledger) -> None:
    ledger.write("stewards/expected-key-ref.txt", "openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432\n")
    assert_fails(ledger.validate(), "expected-key-ref")


def test_case15b_signing_subkey_pin_missing_from_cert_fails(ledger: Ledger) -> None:
    ledger.write("stewards/expected-signing-subkey-ref.txt", "openpgp:0dcd3952b0ba0130e02a5fc70dbbe66fec6d0c67\n")
    assert_fails(ledger.validate(), "expected-signing-subkey-ref")


# --------------------------------------------------------------------------- case 16 (structured first acceptance)


def test_case16_first_accepted_without_structured_evidence_fails_even_with_notes(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(state="accepted", key=key, grade="native-hook", evidence=None,
                      notes="Inspected the constitution on 2026-08-20 and accepted it on 2026-08-24.")
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "evidence")


def test_case16b_missing_acceptance_half_fails(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(state="accepted", key=key, grade="native-hook")
    del doc["adoption"]["evidence"]["acceptance"]
    doc["attestation"]["signature"] = key.sign(doc)
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "acceptance")


def test_case16c_operator_reported_first_accepted_also_needs_evidence(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(state="accepted", fpp_id=key.fpp_id, evidence=None, notes="Operator inspected.")
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "evidence")


# --------------------------------------------------------------------------- cases 20-22 (provenance)


def test_case20_agent_signed_without_signature_fails(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(key=key, sign=False, authorship="agent-signed", filing="self")
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "signature")


def test_case20b_filing_self_requires_agent_signed(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(fpp_id=key.fpp_id, authorship="operator-reported", filing="self")
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "filing")


def test_case20c_agent_signed_without_public_key_fails(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(key=key)
    doc["agent"]["public_key_hex"] = None
    doc["attestation"]["signature"] = key.sign(doc)
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "public_key_hex")


def test_case20d_public_key_must_fingerprint_to_fpp_id(ledger: Ledger) -> None:
    key, other = AgentKey(), AgentKey()
    doc = declaration(key=key, fpp_id=other.fpp_id)
    doc["attestation"]["signature"] = key.sign(doc)
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "fpp_id")


def test_canonical_payload_signature_detects_tampering(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(key=key)
    doc["attestation"]["notes"] = "edited after signing"
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "signature")


def test_case21_operator_reported_accepted_with_claimed_fpp_id_passes(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(state="accepted", fpp_id=key.fpp_id, grade="native-hook")
    ledger.write_yaml(NOVA, doc)
    result = ledger.validate(extra=["--summary"])
    assert_passes(result)
    assert "operator-reported" in output(result)


def test_case22_agent_signed_filing_may_use_fpp_id_claimed_by_operator_report(ledger: Ledger) -> None:
    key = AgentKey()
    ledger.write_yaml("attestations/nova.yaml", declaration(fpp_id=key.fpp_id, contact="github:alice"))
    ledger.write_yaml("attestations/nova--self.yaml", declaration(slug="nova--self", key=key, contact="github:nova"))
    assert_passes(ledger.validate())


def test_two_operator_reports_claiming_same_fpp_id_pass_with_distinct_slugs(ledger: Ledger) -> None:
    key = AgentKey()
    ledger.write_yaml("attestations/nova.yaml", declaration(fpp_id=key.fpp_id, contact="github:alice"))
    ledger.write_yaml("attestations/nova--bob.yaml", declaration(slug="nova--bob", fpp_id=key.fpp_id,
                                                                 contact="github:bob"))
    assert_passes(ledger.validate())


# --------------------------------------------------------------------------- case 24 (lifecycle edges, evidence)


def test_case24a_initial_accepted_from_nothing_fails(ledger: Ledger) -> None:
    key = AgentKey()
    doc = declaration(state="accepted", key=key, grade="native-hook", transition_from=None)
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "transition")


def test_case24b_transition_to_must_equal_lifecycle_state(ledger: Ledger) -> None:
    doc = declaration()
    doc["adoption"]["transition"]["to"] = "accepted"
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "transition")


def test_case24c_disallowed_edge_reviewed_to_revoked_fails(ledger: Ledger) -> None:
    active = declaration()
    active_bytes = ledger.write_yaml(NOVA, active)
    ledger.remove(NOVA)
    ledger.write_yaml("revocations/nova.2026-09-01.yaml", revocation_of(active, NOVA, active_bytes))
    assert_fails(ledger.validate(), "reviewed", "revoked")


@pytest.mark.parametrize(
    "mutation",
    [
        ("inspection", "constitution_hash", "da58a4f3b252bc1727e93876ed0c9e564e3312f049112abddf8519c6f8928058"),
        ("acceptance", "constitution_hash", "0" * 64),
        ("inspection", "inspected_at", "2026-08-24T11:30:00Z"),  # after acceptance
        ("acceptance", "accepted_at", "2026-08-24T13:00:00Z"),  # after transition
    ],
)
def test_case24d_inconsistent_evidence_fails(ledger: Ledger, mutation: tuple[str, str, str]) -> None:
    key = AgentKey()
    doc = declaration(state="accepted", key=key, grade="native-hook")
    part, field, value = mutation
    doc["adoption"]["evidence"][part][field] = value
    doc["attestation"]["signature"] = key.sign(doc)
    ledger.write_yaml(NOVA, doc)
    assert_fails(ledger.validate(), NOVA, "evidence")


# --------------------------------------------------------------------------- cases 25-26, 13, 23 (git-aware intake)


def test_valid_amend_passes_in_intake_mode(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(key=key)
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    base = git_ledger.commit("v1")
    git_ledger.write_yaml(NOVA, successor(v1, NOVA, v1_bytes, key=key, **{"attestation.notes": "tooling bump"}))
    _, result = intake(git_ledger, base, actor="anyone", head_repo="anyone/fpp-attestation-ledger")
    assert_passes(result)


def test_amend_without_version_bump_fails(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(key=key)
    git_ledger.write_yaml(NOVA, v1)
    base = git_ledger.commit("v1")
    edited = copy.deepcopy(v1)
    edited["attestation"]["notes"] = "silently edited"
    edited["attestation"]["signature"] = key.sign(edited)
    git_ledger.write_yaml(NOVA, edited)
    _, result = intake(git_ledger, base)
    assert_fails(result, NOVA, "version")


def test_amend_with_wrong_predecessor_hash_fails(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(key=key)
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    base = git_ledger.commit("v1")
    v2 = successor(v1, NOVA, v1_bytes, key=key)
    v2["attestation"]["predecessor_record"]["sha256"] = "0" * 64
    v2["attestation"]["signature"] = key.sign(v2)
    git_ledger.write_yaml(NOVA, v2)
    _, result = intake(git_ledger, base)
    assert_fails(result, NOVA, "predecessor_record")


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent.fpp_id", "fpp:ed25519:" + "a" * 64),
        ("agent.public_key_hex", "b" * 64),
        ("attestation.authorship", "operator-reported"),
        ("operator.contact", "github:mallory"),
        ("operator.name", "Mallory"),
        ("attestation.declaration_id", "00000000-0000-4000-8000-000000000000"),
    ],
)
def test_case25_amend_changing_identity_or_provenance_fails(git_ledger: Ledger, field: str, value: str) -> None:
    key = AgentKey()
    v1 = declaration(key=key)
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    base = git_ledger.commit("v1")
    v2 = successor(v1, NOVA, v1_bytes)
    section, name = field.split(".")
    v2[section][name] = value
    if v2["attestation"]["authorship"] == "operator-reported":
        v2["attestation"]["filing"] = "operator"
        v2["attestation"]["signature"] = None
    else:
        v2["attestation"]["signature"] = key.sign(v2)
    git_ledger.write_yaml(NOVA, v2)
    _, result = intake(git_ledger, base)
    assert_fails(result, NOVA, name)


def test_correct_declaration_may_upgrade_provenance_in_intake_mode(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(fpp_id=key.fpp_id, contact="github:alice")
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    base = git_ledger.commit("v1")
    v2 = successor(v1, NOVA, v1_bytes, key=key,
                   **{"attestation.authorship": "agent-signed", "attestation.filing": "self",
                      "attestation.action": "correct-declaration", "agent.public_key_hex": key.public_key_hex})
    v2["attestation"]["signature"] = key.sign(v2)
    git_ledger.write_yaml(NOVA, v2)
    _, result = intake(git_ledger, base, actor="courier", head_repo="courier/fpp-attestation-ledger", head_ref="x")
    assert_passes(result)


def test_declaration_action_must_match_version_and_path(git_ledger: Ledger) -> None:
    doc = declaration()
    doc["attestation"]["action"] = "amend"  # version 1 cannot be an amendment
    git_ledger.write_yaml(NOVA, doc)
    assert_fails(git_ledger.validate(), NOVA, "action")


def test_case25b_amend_changing_slug_fails(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(key=key)
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    base = git_ledger.commit("v1")
    v2 = successor(v1, NOVA, v1_bytes, key=key, **{"agent.slug": "nova-prime"})
    git_ledger.remove(NOVA)
    git_ledger.write_yaml("attestations/nova-prime.yaml", v2)
    _, result = intake(git_ledger, base)
    assert_fails(result, "slug")


def test_case26_intake_deleting_declaration_fails(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    base = git_ledger.commit("v1")
    git_ledger.remove(NOVA)
    _, result = intake(git_ledger, base)
    assert_fails(result, NOVA, "delet")


def test_case26b_intake_modifying_revocation_fails(git_ledger: Ledger) -> None:
    key = AgentKey()
    active = declaration(key=key, state="accepted", grade="native-hook")
    active_bytes = git_ledger.write_yaml(NOVA, active)
    git_ledger.commit("accepted v1")
    git_ledger.remove(NOVA)
    rev = revocation_of(active, NOVA, active_bytes, key=key)
    rev_path = "revocations/nova.2026-09-01.yaml"
    git_ledger.write_yaml(rev_path, rev)
    base = git_ledger.commit("withdrawn")
    rev["attestation"]["reason"] = "edited history"
    rev["attestation"]["signature"] = key.sign(rev)
    git_ledger.write_yaml(rev_path, rev)
    _, result = intake(git_ledger, base)
    assert_fails(result, rev_path)


def test_withdraw_adoption_move_passes_in_intake_mode(git_ledger: Ledger) -> None:
    key = AgentKey()
    active = declaration(key=key, state="accepted", grade="native-hook")
    active_bytes = git_ledger.write_yaml(NOVA, active)
    base = git_ledger.commit("accepted v1")
    git_ledger.remove(NOVA)
    git_ledger.write_yaml("revocations/nova.2026-09-01.yaml", revocation_of(active, NOVA, active_bytes, key=key))
    _, result = intake(git_ledger, base)
    assert_passes(result)


def test_case13_intake_adding_steward_asc_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.write(git_ledger.record_sig_name(NOVA), "-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n")
    _, result = intake(git_ledger, base)
    assert_fails(result, ".record.asc")


def test_case13b_intake_adding_admission_event_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.write("admissions/nova.deadbeef.0001.json", "{}")
    _, result = intake(git_ledger, base)
    assert_fails(result, "admissions/")


def test_case26c_intake_touching_protected_paths_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write("stewards/authorized-github-actors.txt", "mallory\n")
    _, result = intake(git_ledger, base)
    assert_fails(result, "stewards/")


def test_case23_operator_authority_actor_mismatch_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(contact="github:alice"))
    _, result = intake(git_ledger, base, actor="bob", author="alice")
    assert_fails(result, "authority", "github:alice")


def test_case23b_operator_authority_fork_owner_mismatch_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(contact="github:alice"))
    _, result = intake(git_ledger, base, actor="alice", head_repo="mallory/fpp-attestation-ledger")
    assert_fails(result, "authority")


def test_case23c_operator_authority_base_branch_prefix_mismatch_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(contact="github:alice"))
    _, result = intake(git_ledger, base, actor="alice", head_ref="feature/nova")
    assert_fails(result, "intake/alice/")


def test_case23d_operator_authority_match_passes_for_fork_and_scoped_branch(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(contact="github:alice"))
    _, result = intake(git_ledger, base, actor="Alice", head_repo="Alice/fpp-attestation-ledger", head_ref="x")
    assert_passes(result)
    git_ledger.write_yaml("attestations/nova--two.yaml", declaration(slug="nova--two", contact="github:alice"))
    _, result = intake(git_ledger, base, actor="alice")
    assert_passes(result)


def test_case23e_operator_contact_must_be_lowercase_github_login_on_github_path(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(contact="github:Alice"))
    _, result = intake(git_ledger, base, actor="alice")
    assert_fails(result, "github:")


def test_case23f_non_github_contact_requires_steward_transport(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(contact="mailto:ops@example.org"))
    _, result = intake(git_ledger, base, actor="alice")
    assert_fails(result, "out-of-band")
    _, result = intake(git_ledger, base, actor=STEWARD_LOGIN, head_ref=f"intake/{STEWARD_LOGIN}/nova")
    assert_passes(result)


def test_case23g_workflow_rerun_events_do_not_supply_authority(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(contact="github:alice"))
    _, result = intake(git_ledger, base, actor="alice", event_action="labeled")
    assert_fails(result, "authority")


def test_agent_signed_filing_is_authorized_by_signature_regardless_of_transport(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration(key=AgentKey(), contact="mailto:ops@example.org"))
    _, result = intake(git_ledger, base, actor="courier", head_repo="courier/fpp-attestation-ledger", head_ref="x")
    assert_passes(result)


def test_amend_of_operator_reported_lineage_requires_same_authority(git_ledger: Ledger) -> None:
    v1 = declaration(contact="github:alice")
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    base = git_ledger.commit("v1")
    git_ledger.write_yaml(NOVA, successor(v1, NOVA, v1_bytes, **{"attestation.notes": "bob edits"}))
    _, result = intake(git_ledger, base, actor="bob", head_ref="intake/bob/nova")
    assert_fails(result, "authority")


def test_intake_head_sha_must_match_context(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.commit("pr")
    ctx = git_ledger.context(head_sha="1" * 40, base_sha=base, head_ref="intake/alice/nova",
                             head_repo="FIDES-ANIMA/fpp-attestation-ledger")
    assert_fails(git_ledger.validate("intake", base_ref=base, context=ctx), "head")


# --------------------------------------------------------------------------- fail-closed behavior


def test_intake_mode_requires_base_ref_and_context(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.commit("pr")
    assert_fails(git_ledger.validate("intake"), "--base-ref")
    assert_fails(git_ledger.validate("intake", base_ref=base), "--context")


def test_release_modes_fail_closed_without_git_history(ledger: Ledger) -> None:
    ledger.write_yaml(NOVA, declaration())
    assert_fails(ledger.validate("main"), "history")


def test_main_mode_with_history_passes_and_lists_lineage_heads(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(key=key)
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    git_ledger.commit("v1")
    git_ledger.write_yaml(NOVA, successor(v1, NOVA, v1_bytes, key=key, **{"attestation.notes": "amended"}))
    git_ledger.commit("v2")
    result = git_ledger.validate("main", extra=["--summary"])
    assert_passes(result)
    text = output(result)
    assert "version 2" in text or "v2" in text


def test_main_mode_rejects_predecessor_bytes_absent_from_history(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(key=key)
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    v2 = successor(v1, NOVA, v1_bytes, key=key)
    git_ledger.write_yaml(NOVA, v2)  # v1 bytes never committed
    git_ledger.commit("only v2")
    assert_fails(git_ledger.validate("main"), NOVA, "predecessor")


def test_main_mode_rejects_history_that_deleted_an_admission_artifact(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    git_ledger.commit("admitted")
    git_ledger.remove(git_ledger.event_name(NOVA, 1))
    git_ledger.commit("oops")
    assert_fails(git_ledger.validate("main"), "admissions/")


def test_main_mode_rejects_history_that_rewrote_a_revocation(git_ledger: Ledger) -> None:
    key = AgentKey()
    active = declaration(key=key, state="accepted", grade="native-hook")
    active_bytes = git_ledger.write_yaml(NOVA, active)
    git_ledger.commit("v1")
    git_ledger.remove(NOVA)
    rev = revocation_of(active, NOVA, active_bytes, key=key)
    rev_path = "revocations/nova.2026-09-01.yaml"
    git_ledger.write_yaml(rev_path, rev)
    git_ledger.commit("withdrawn")
    rev["attestation"]["reason"] = "rewritten"
    rev["attestation"]["signature"] = key.sign(rev)
    git_ledger.write_yaml(rev_path, rev)
    git_ledger.commit("rewrite")
    assert_fails(git_ledger.validate("main"), rev_path)


def test_yaml_parse_error_is_reported_per_file(ledger: Ledger) -> None:
    ledger.write(NOVA, "agent: [unclosed\n")
    assert_fails(ledger.validate(), NOVA)


def test_validator_reads_declaration_as_single_mapping(ledger: Ledger) -> None:
    doc = declaration()
    ledger.write(NOVA, yaml.safe_dump(doc) + "---\nagent: {}\n")
    assert_fails(ledger.validate(), NOVA)


def test_constitution_hash_constant_is_the_json_hash() -> None:
    assert CONSTITUTION_HASH.startswith("71bf60ad")
