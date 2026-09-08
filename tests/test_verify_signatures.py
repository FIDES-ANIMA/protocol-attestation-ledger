"""Admission-side contract for scripts/verify-signatures.py (and admission-mode validate.py).

Case numbers refer to docs/plans/2026-08-30-fpp-attestation-ledger-v1-staged.md §D2.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import yaml

from .conftest import (
    FAKE_PAST,
    REPOSITORY,
    STEWARD_LOGIN,
    AgentKey,
    Ledger,
    assert_fails,
    assert_passes,
    declaration,
    output,
    revocation_of,
    sha256_bytes,
    successor,
)

NOVA = "attestations/nova.yaml"


def admission(
    ledger: Ledger,
    base: str,
    *,
    sign: bool = True,
    subkey: str | None = None,
    actor: str = STEWARD_LOGIN,
    head_ref: str = "admission/nova-attest",
    head_repo: str = REPOSITORY,
) -> tuple[str, subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]]:
    head = ledger.commit("admission candidate", sign=sign, subkey=subkey)
    ctx = ledger.context(
        head_sha=head, base_sha=base, actor=actor, head_ref=head_ref, head_repo=head_repo, event_action="opened"
    )
    return (
        head,
        ledger.verify("admission", base_ref=base, context=ctx),
        ledger.validate("admission", base_ref=base, context=ctx),
    )


def load_event(ledger: Ledger, rel: str) -> dict:
    return json.loads(ledger.read(rel))


# --------------------------------------------------------------------------- baseline


def test_main_mode_empty_tree_passes(git_ledger: Ledger) -> None:
    git_ledger.commit("empty")
    assert_passes(git_ledger.verify("main"))


def test_main_mode_requires_record_signature_and_admit_event(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.commit("unsigned declaration on main")
    assert_fails(git_ledger.verify("main"), NOVA, ".record.asc")


def test_main_mode_valid_admitted_record_passes_and_reports_status(git_ledger: Ledger) -> None:
    key = AgentKey()
    git_ledger.write_yaml(NOVA, declaration(key=key))
    git_ledger.admit(NOVA)
    git_ledger.commit("admitted")
    result = git_ledger.verify("main")
    assert_passes(result)
    text = output(result)
    assert "admitted" in text and "agent-signed" in text


def test_main_mode_requires_event_signature(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    event = git_ledger.admit(NOVA)
    git_ledger.remove(event + ".asc")
    git_ledger.commit("missing event sig")
    assert_fails(git_ledger.verify("main"), event + ".asc")


def test_main_mode_rejects_bad_signature_bytes(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    sig = git_ledger.record_sig_name(NOVA)
    other = git_ledger.write("scratch.txt", "other bytes\n")
    git_ledger.steward.sign_detached(git_ledger.path("scratch.txt"), git_ledger.path(sig))
    git_ledger.remove("scratch.txt")
    assert other
    git_ledger.commit("wrong sig")
    assert_fails(git_ledger.verify("main"), sig)


def test_main_mode_rejects_signature_from_unknown_key(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    event = git_ledger.admit(NOVA)
    git_ledger.write(event + ".asc", "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n-----END PGP SIGNATURE-----\n")
    git_ledger.commit("garbage sig")
    assert_fails(git_ledger.verify("main"), event + ".asc")


def test_verifier_never_requires_git_free_release_mode(ledger: Ledger) -> None:
    ledger.write_yaml(NOVA, declaration())
    assert_fails(ledger.verify("main"), "history")


# --------------------------------------------------------------------------- case 15 (pins)


def test_case15_cert_fingerprint_mismatch_fails(git_ledger: Ledger) -> None:
    git_ledger.write("stewards/expected-key-ref.txt", "openpgp:715e182192c546a612f8e6d64a9e2aff11cb1432\n")
    git_ledger.commit("bad pin")
    assert_fails(git_ledger.verify("main"), "expected-key-ref")


def test_case15b_signing_subkey_pin_must_belong_to_cert(git_ledger: Ledger) -> None:
    git_ledger.write("stewards/expected-signing-subkey-ref.txt", "openpgp:" + "0" * 40 + "\n")
    git_ledger.commit("bad subkey pin")
    assert_fails(git_ledger.verify("main"), "expected-signing-subkey-ref")


def test_cert_containing_secret_armor_fails(git_ledger: Ledger) -> None:
    from .conftest import PRIVATE_ARMOR

    git_ledger.write("stewards/fides-anima.asc", git_ledger.steward.public_armor + PRIVATE_ARMOR.encode())
    git_ledger.commit("leak")
    assert_fails(git_ledger.verify("main"), "stewards/fides-anima.asc")


# --------------------------------------------------------------------------- case 13 / 29 (intake prohibitions)


def test_case13_intake_mode_rejects_added_steward_signature(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.steward.sign_detached(git_ledger.path(NOVA), git_ledger.path(git_ledger.record_sig_name(NOVA)))
    head = git_ledger.commit("pr with asc")
    ctx = git_ledger.context(
        head_sha=head, base_sha=base, head_ref="intake/alice/nova", head_repo="FIDES-ANIMA/fpp-attestation-ledger"
    )
    assert_fails(git_ledger.verify("intake", base_ref=base, context=ctx), ".record.asc")


def test_case13b_intake_mode_rejects_added_admission_event(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.write("admissions/nova.abc.0001.json", "{}\n")
    head = git_ledger.commit("pr with event")
    ctx = git_ledger.context(
        head_sha=head, base_sha=base, head_ref="intake/alice/nova", head_repo="FIDES-ANIMA/fpp-attestation-ledger"
    )
    assert_fails(git_ledger.verify("intake", base_ref=base, context=ctx), "admissions/")


def test_intake_mode_clean_declaration_change_passes(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    head = git_ledger.commit("pr")
    ctx = git_ledger.context(
        head_sha=head, base_sha=base, head_ref="intake/alice/nova", head_repo="FIDES-ANIMA/fpp-attestation-ledger"
    )
    assert_passes(git_ledger.verify("intake", base_ref=base, context=ctx))


def test_intake_mode_requires_base_ref_matching_context(git_ledger: Ledger) -> None:
    base = git_ledger.commit("empty")
    git_ledger.write_yaml(NOVA, declaration())
    head = git_ledger.commit("pr")
    ctx = git_ledger.context(
        head_sha=head, base_sha="2" * 40, head_ref="intake/alice/nova", head_repo="FIDES-ANIMA/fpp-attestation-ledger"
    )
    assert_fails(git_ledger.verify("intake", base_ref=base, context=ctx), "base")
    assert_fails(git_ledger.verify("intake", context=ctx), "--base-ref")


# --------------------------------------------------------------------------- case 17 (expired subkey)


def test_case17_historical_artifact_signed_by_since_expired_subkey_is_accepted_with_diagnostic(
    git_ledger: Ledger,
) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA, subkey=git_ledger.steward.expired, faked_time=FAKE_PAST)
    git_ledger.commit("historical admission")
    result = git_ledger.verify("main")
    assert_passes(result)
    assert "expired" in output(result).lower()
    assert git_ledger.steward.expired.lower() in output(result).lower()


def test_case17b_admission_diff_artifact_signed_by_expired_subkey_fails_explicitly(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA, subkey=git_ledger.steward.expired, faked_time=FAKE_PAST)
    _, verify, _ = admission(git_ledger, base)
    assert_fails(verify, "expired", git_ledger.steward.signing.lower())
    assert "Traceback" not in output(verify)


def test_case17c_admission_diff_artifact_must_use_pinned_signing_subkey(git_ledger: Ledger) -> None:
    """A non-pinned but currently valid subkey is also rejected for new artifacts."""
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    git_ledger.write("stewards/expected-signing-subkey-ref.txt", f"openpgp:{git_ledger.steward.expired.lower()}\n")
    _, verify, _ = admission(git_ledger, base)
    assert_fails(verify, "expected-signing-subkey-ref")


# --------------------------------------------------------------------------- cases 18-19 (admission withdrawal)


def test_case18_withdraw_admission_leaves_declaration_bytes_and_lifecycle_unchanged(git_ledger: Ledger) -> None:
    key = AgentKey()
    original = git_ledger.write_yaml(NOVA, declaration(key=key, state="accepted", grade="native-hook"))
    first = git_ledger.admit(NOVA)
    base = git_ledger.commit("admitted")
    git_ledger.append_event(
        NOVA,
        git_ledger.sha256(NOVA),
        2,
        action="withdraw-admission",
        status="withdrawn",
        previous=first,
        reason="Impersonation report upheld; publication withdrawn.",
    )
    _, verify, validate = admission(git_ledger, base, head_ref="admission/nova-withdraw")
    assert_passes(verify)
    assert_passes(validate)
    assert git_ledger.read(NOVA) == original
    assert yaml.safe_load(original)["adoption"]["lifecycle_state"] == "accepted"
    result = git_ledger.verify("main")
    assert_passes(result)
    assert "withdrawn" in output(result)


def test_case19_steward_cannot_set_lifecycle_revoked_while_withdrawing_admission(git_ledger: Ledger) -> None:
    key = AgentKey()
    active = declaration(key=key, state="accepted", grade="native-hook")
    active_bytes = git_ledger.write_yaml(NOVA, active)
    first = git_ledger.admit(NOVA)
    base = git_ledger.commit("admitted")
    record_sha = git_ledger.sha256(NOVA)
    git_ledger.append_event(NOVA, record_sha, 2, action="withdraw-admission", status="withdrawn", previous=first)
    git_ledger.remove(NOVA)
    rev = revocation_of(active, NOVA, active_bytes, key=key)
    git_ledger.write_yaml("revocations/nova.2026-09-01.yaml", rev)
    _, verify, validate = admission(git_ledger, base, head_ref="admission/nova-withdraw")
    assert verify.returncode != 0 or validate.returncode != 0
    assert "lifecycle" in (output(verify) + output(validate)).lower()


def test_case19b_admission_only_event_with_in_place_lifecycle_edit_fails(git_ledger: Ledger) -> None:
    key = AgentKey()
    active = declaration(key=key, state="accepted", grade="native-hook")
    git_ledger.write_yaml(NOVA, active)
    first = git_ledger.admit(NOVA)
    base = git_ledger.commit("admitted")
    record_sha = git_ledger.sha256(NOVA)
    git_ledger.append_event(NOVA, record_sha, 2, action="withdraw-admission", status="withdrawn", previous=first)
    active["adoption"]["lifecycle_state"] = "revoked"
    git_ledger.write_yaml(NOVA, active)
    _, verify, validate = admission(git_ledger, base, head_ref="admission/nova-withdraw")
    assert verify.returncode != 0 or validate.returncode != 0


def test_reinstate_after_withdrawal_passes(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    first = git_ledger.admit(NOVA)
    sha = git_ledger.sha256(NOVA)
    second = git_ledger.append_event(NOVA, sha, 2, action="withdraw-admission", status="withdrawn", previous=first)
    git_ledger.append_event(NOVA, sha, 3, action="reinstate-admission", status="admitted", previous=second)
    git_ledger.commit("reinstated")
    result = git_ledger.verify("main")
    assert_passes(result)
    assert "admitted" in output(result)


# --------------------------------------------------------------------------- case 27 (chain integrity)


def test_case27a_sequence_gap_fails(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    first = git_ledger.admit(NOVA)
    sha = git_ledger.sha256(NOVA)
    git_ledger.append_event(NOVA, sha, 3, action="withdraw-admission", status="withdrawn", previous=first)
    git_ledger.commit("gap")
    assert_fails(git_ledger.verify("main"), "sequence")


def test_case27b_broken_previous_event_hash_fails(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    first = git_ledger.admit(NOVA)
    sha = git_ledger.sha256(NOVA)
    event = git_ledger.event_template(
        NOVA, seq=2, action="withdraw-admission", declaration_action=None, status="withdrawn", previous=first
    )
    event["previousEvent"]["sha256"] = "0" * 64
    git_ledger.write_event(f"admissions/nova.{sha}.0002.json", event)
    git_ledger.commit("broken chain")
    assert_fails(git_ledger.verify("main"), "previousEvent")


def test_case27c_missing_reason_or_wrong_actor_fails(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    event = git_ledger.event_template(NOVA)
    event["reason"] = ""
    git_ledger.steward.sign_detached(git_ledger.path(NOVA), git_ledger.path(git_ledger.record_sig_name(NOVA)))
    rel = git_ledger.write_event(git_ledger.event_name(NOVA, 1), event)
    git_ledger.commit("empty reason")
    assert_fails(git_ledger.verify("main"), rel, "reason")
    event["reason"] = "ok"
    event["actor"]["type"] = "operator"
    git_ledger.write_event(rel, event)
    git_ledger.commit("wrong actor")
    assert_fails(git_ledger.verify("main"), rel, "actor")


def test_case27d_actor_key_ref_must_be_pinned_primary(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    event = git_ledger.event_template(NOVA)
    event["actor"]["keyRef"] = "openpgp:" + "1" * 40
    git_ledger.steward.sign_detached(git_ledger.path(NOVA), git_ledger.path(git_ledger.record_sig_name(NOVA)))
    rel = git_ledger.write_event(git_ledger.event_name(NOVA, 1), event)
    git_ledger.commit("wrong keyref")
    assert_fails(git_ledger.verify("main"), rel, "keyRef")


def test_case27e_invalid_status_edge_fails(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    first = git_ledger.admit(NOVA)
    sha = git_ledger.sha256(NOVA)
    second = git_ledger.append_event(NOVA, sha, 2, action="withdraw-admission", status="withdrawn", previous=first)
    git_ledger.append_event(NOVA, sha, 3, action="mark-disputed", status="disputed", previous=second)
    git_ledger.commit("bad edge")
    assert_fails(git_ledger.verify("main"), "withdrawn", "mark-disputed")


def test_case27f_first_event_must_be_admit(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.steward.sign_detached(git_ledger.path(NOVA), git_ledger.path(git_ledger.record_sig_name(NOVA)))
    event = git_ledger.event_template(NOVA, action="withdraw-admission", declaration_action=None, status="withdrawn")
    rel = git_ledger.write_event(git_ledger.event_name(NOVA, 1), event)
    git_ledger.commit("bad first")
    assert_fails(git_ledger.verify("main"), rel)


def test_case27g_record_hash_must_match_filename_and_bytes(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    event_rel = git_ledger.event_name(NOVA, 1)
    event = load_event(git_ledger, event_rel)
    event["record"]["sha256"] = "f" * 64
    git_ledger.write_event(event_rel, event)
    git_ledger.commit("hash mismatch")
    assert_fails(git_ledger.verify("main"), event_rel, "sha256")


def test_case27h_event_for_unknown_record_fails(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    git_ledger.remove(NOVA)
    git_ledger.commit("record never existed in history")
    assert_fails(git_ledger.verify("main"), "admissions/nova.")


def test_case27i_event_must_validate_against_event_schema(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    event = git_ledger.event_template(NOVA)
    del event["authority"]
    git_ledger.steward.sign_detached(git_ledger.path(NOVA), git_ledger.path(git_ledger.record_sig_name(NOVA)))
    rel = git_ledger.write_event(git_ledger.event_name(NOVA, 1), event)
    git_ledger.commit("schema violation")
    assert_fails(git_ledger.verify("main"), rel, "authority")


def test_admit_event_review_hashes_must_match_declaration_bytes(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    event = git_ledger.event_template(NOVA)
    event["review"]["declarationHashes"][NOVA] = "e" * 64
    git_ledger.steward.sign_detached(git_ledger.path(NOVA), git_ledger.path(git_ledger.record_sig_name(NOVA)))
    rel = git_ledger.write_event(git_ledger.event_name(NOVA, 1), event)
    git_ledger.commit("review mismatch")
    assert_fails(git_ledger.verify("main"), rel, "declarationHashes")


# --------------------------------------------------------------------------- case 28 (correction)


def _admit_corrected_lineage(git_ledger: Ledger, *, reciprocal: bool = True) -> tuple[str, str]:
    key = AgentKey()
    v1 = declaration(fpp_id=key.fpp_id, contact="github:alice")
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    v1_sha = sha256_bytes(v1_bytes)
    v1_event = git_ledger.admit(NOVA)
    git_ledger.commit("v1 admitted")
    v2 = successor(
        v1,
        NOVA,
        v1_bytes,
        key=key,
        **{
            "attestation.authorship": "agent-signed",
            "attestation.filing": "self",
            "attestation.action": "correct-declaration",
            "agent.public_key_hex": key.public_key_hex,
        },
    )
    v2["attestation"]["signature"] = key.sign(v2)
    v2_bytes = git_ledger.write_yaml(NOVA, v2)
    v2_event = git_ledger.admit(NOVA, declaration_action="correct-declaration")
    correction = git_ledger.event_template(
        NOVA,
        seq=2,
        action="correct-admission",
        declaration_action=None,
        status="corrected",
        previous=v1_event,
        record_bytes=v1_bytes,
    )
    correction["correctionRef"] = {
        "declarationId": v2["attestation"]["declaration_id"],
        "version": 2,
        "path": NOVA,
        "sha256": sha256_bytes(v2_bytes) if reciprocal else "0" * 64,
        "admissionEvent": {"path": v2_event, "sha256": git_ledger.sha256(v2_event)},
    }
    git_ledger.write_event(f"admissions/nova.{v1_sha}.0002.json", correction)
    git_ledger.commit("v2 admitted, v1 corrected")
    return v1_sha, sha256_bytes(v2_bytes)


def test_case28_correction_links_both_histories_and_current_set_is_lineage_head(git_ledger: Ledger) -> None:
    v1_sha, v2_sha = _admit_corrected_lineage(git_ledger)
    result = git_ledger.verify("main")
    assert_passes(result)
    text = output(result)
    assert "corrected" in text and "agent-signed" in text
    assert v2_sha in text
    validate = git_ledger.validate("main", extra=["--summary"])
    assert_passes(validate)
    assert "agent-signed: 1" in output(validate)
    assert "operator-reported: 0" in output(validate)


def test_case28b_correction_without_reciprocal_hash_fails(git_ledger: Ledger) -> None:
    _admit_corrected_lineage(git_ledger, reciprocal=False)
    assert_fails(git_ledger.verify("main"), "correctionRef")


def test_case28c_correct_declaration_requires_correct_admission_on_old_record(git_ledger: Ledger) -> None:
    key = AgentKey()
    v1 = declaration(fpp_id=key.fpp_id)
    v1_bytes = git_ledger.write_yaml(NOVA, v1)
    git_ledger.admit(NOVA)
    git_ledger.commit("v1")
    v2 = successor(
        v1,
        NOVA,
        v1_bytes,
        key=key,
        **{
            "attestation.authorship": "agent-signed",
            "attestation.filing": "self",
            "attestation.action": "correct-declaration",
            "agent.public_key_hex": key.public_key_hex,
        },
    )
    v2["attestation"]["signature"] = key.sign(v2)
    git_ledger.write_yaml(NOVA, v2)
    git_ledger.admit(NOVA, declaration_action="correct-declaration")
    git_ledger.commit("v2 without correct-admission")
    assert_fails(git_ledger.verify("main"), "correct-admission")


def test_admit_event_declaration_action_must_match_record(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA, declaration_action="amend")
    git_ledger.commit("mismatch")
    assert_fails(git_ledger.verify("main"), "declarationAction")


# --------------------------------------------------------------------------- case 29 (admission mode)


def test_case29_admission_mode_valid_candidate_passes(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    _, verify, validate = admission(git_ledger, base)
    assert_passes(verify)
    assert_passes(validate)


def test_case29a_admission_mode_missing_record_signature_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    git_ledger.remove(git_ledger.record_sig_name(NOVA))
    _, verify, _ = admission(git_ledger, base)
    assert_fails(verify, ".record.asc")


def test_case29b_admission_mode_missing_event_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.steward.sign_detached(git_ledger.path(NOVA), git_ledger.path(git_ledger.record_sig_name(NOVA)))
    _, verify, _ = admission(git_ledger, base)
    assert_fails(verify, "0001")


def test_case29c_admission_mode_changed_reviewed_bytes_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    doc = declaration()
    git_ledger.write_yaml(NOVA, doc)
    git_ledger.admit(NOVA, head_sha="a" * 40)
    doc["attestation"]["notes"] = "changed after review"
    git_ledger.write_yaml(NOVA, doc)  # event and .record.asc now point at the old bytes
    _, verify, _ = admission(git_ledger, base)
    assert_fails(verify, NOVA)


def test_case29d_admission_mode_unsigned_head_commit_fails(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    _, verify, _ = admission(git_ledger, base, sign=False)
    assert_fails(verify, "commit")


def test_case29e_admission_mode_requires_admission_branch_in_base_repo(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    _, verify, validate = admission(git_ledger, base, head_ref="feature/nova")
    assert_fails(verify, "admission/")
    assert_fails(validate, "admission/")
    git_ledger.commit("again")
    _, verify, validate = admission(git_ledger, base, head_repo="steward-bot/fpp-attestation-ledger")
    assert_fails(verify, "base repository")


def test_case29f_admission_mode_requires_allowlisted_actor(git_ledger: Ledger) -> None:
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    _, verify, validate = admission(git_ledger, base, actor="mallory")
    assert_fails(verify, "mallory")
    assert_fails(validate, "mallory")


def test_case29g_admission_mode_fails_closed_without_allowlist(git_ledger: Ledger) -> None:
    git_ledger.remove("stewards/authorized-github-actors.txt")
    base = git_ledger.commit("main")
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    _, verify, _ = admission(git_ledger, base)
    assert_fails(verify, "authorized-github-actors")


def test_case29h_admission_mode_requires_fast_forward_from_base(git_ledger: Ledger) -> None:
    older = git_ledger.commit("older")
    git_ledger.write("README.md", "moved main\n")
    base = git_ledger.commit("current main")
    git_ledger.git("checkout", "-q", "-b", "admission/x", older)
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    _, verify, _ = admission(git_ledger, base)
    assert_fails(verify, "ancestor")


def test_case29i_admission_mode_rejects_modified_existing_artifact(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    event = git_ledger.admit(NOVA)
    base = git_ledger.commit("admitted")
    data = load_event(git_ledger, event)
    data["reason"] = "rewritten"
    git_ledger.write_event(event, data)
    _, verify, _ = admission(git_ledger, base, head_ref="admission/rewrite")
    assert_fails(verify, event)


# --------------------------------------------------------------------------- slug release


def _withdraw_then_release(git_ledger: Ledger, *, release: bool) -> None:
    alice = AgentKey()
    active = declaration(key=alice, state="accepted", grade="native-hook")
    active_bytes = git_ledger.write_yaml(NOVA, active)
    git_ledger.admit(NOVA)
    git_ledger.commit("alice admitted")
    git_ledger.remove(NOVA)
    rev_path = "revocations/nova.2026-09-01.yaml"
    git_ledger.write_yaml(rev_path, revocation_of(active, NOVA, active_bytes, key=alice))
    first = git_ledger.admit(rev_path, declaration_action="withdraw-adoption")
    sha = git_ledger.sha256(rev_path)
    second = git_ledger.append_event(
        rev_path,
        sha,
        2,
        action="withdraw-admission",
        status="withdrawn",
        previous=first,
        reason="Original principal confirmed gone.",
    )
    if release:
        event = git_ledger.event_template(
            rev_path, seq=3, action="slug-release", declaration_action=None, status="withdrawn", previous=second
        )
        event["slugReleased"] = True
        git_ledger.write_event(f"admissions/nova.{sha}.0003.json", event)
    git_ledger.commit("alice lineage withdrawn")
    git_ledger.write_yaml(NOVA, declaration(key=AgentKey(), contact="github:bob"))
    git_ledger.admit(NOVA)
    git_ledger.commit("bob takes nova")


def test_slug_release_allows_new_lineage_to_take_slug(git_ledger: Ledger) -> None:
    _withdraw_then_release(git_ledger, release=True)
    assert_passes(git_ledger.verify("main"))
    assert_passes(git_ledger.validate("main"))


def test_without_slug_release_new_lineage_is_rejected(git_ledger: Ledger) -> None:
    _withdraw_then_release(git_ledger, release=False)
    assert_fails(git_ledger.validate("main"), NOVA, "slug-release")


def test_slug_release_from_admitted_status_fails(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    first = git_ledger.admit(NOVA)
    sha = git_ledger.sha256(NOVA)
    event = git_ledger.event_template(
        NOVA, seq=2, action="slug-release", declaration_action=None, status="admitted", previous=first
    )
    event["slugReleased"] = True
    git_ledger.write_event(f"admissions/nova.{sha}.0002.json", event)
    git_ledger.commit("bad release")
    assert_fails(git_ledger.verify("main"), "slug-release")


# --------------------------------------------------------------------------- hygiene


def test_temporary_gnupghome_is_always_deleted(git_ledger: Ledger, tmp_path: Path) -> None:
    scratch = tmp_path / "scratch-tmp"
    scratch.mkdir()
    env = {"TMPDIR": str(scratch), "TEMP": str(scratch), "TMP": str(scratch)}
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    git_ledger.commit("ok")
    assert_passes(git_ledger.verify("main", env=env))
    assert list(scratch.iterdir()) == []
    git_ledger.write("stewards/expected-key-ref.txt", "openpgp:" + "9" * 40 + "\n")
    git_ledger.commit("bad")
    assert git_ledger.verify("main", env=env).returncode != 0
    assert list(scratch.iterdir()) == []


def test_verifier_ignores_ambient_gnupghome_and_only_imports_committed_cert(git_ledger: Ledger, tmp_path: Path) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    git_ledger.commit("ok")
    env = {"GNUPGHOME": str(tmp_path / "does-not-exist")}
    assert_passes(git_ledger.verify("main", env=env))
    assert not (tmp_path / "does-not-exist").exists()


def test_verifier_output_never_claims_compliance(git_ledger: Ledger) -> None:
    git_ledger.write_yaml(NOVA, declaration())
    git_ledger.admit(NOVA)
    git_ledger.commit("ok")
    text = output(git_ledger.verify("main")).lower()
    assert "declaration-only" in text
    assert "compliant" not in text and "peer-advertisable" not in text
    assert os.linesep  # keep os import meaningful on all platforms
