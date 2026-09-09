#!/usr/bin/env python3
"""Validate FPP attestation ledger declarations, lineage, provenance, authority, and history.

Modes:
  working    structural and current-tree checks only; never release evidence
  intake     contributor PR: declaration changes only, against an immutable --base-ref
  admission  steward admission/* branch: full candidate tree plus admission artifacts
  main       published tree with full first-parent history

Exit codes: 0 valid, 1 invalid, 2 fail-closed (required base, context, or history unavailable).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledgerlib as L  # noqa: E402

RELEASE_MODES = ("intake", "admission", "main")


# --------------------------------------------------------------------------- per-record rules


def check_record(rec: L.Record, validator: Any, report: Report) -> None:
    path = rec.path
    for msg in L.schema_errors(validator, rec.doc):
        report.error(path, f"schema: {msg}")
    if (
        not isinstance(rec.doc.get("agent"), dict)
        or not isinstance(rec.doc.get("adoption"), dict)
        or not isinstance(rec.doc.get("attestation"), dict)
    ):
        return

    slug = rec.slug
    state = rec.state
    m_active = L.ACTIVE_PATH_RE.match(path)
    m_revoked = L.REVOKED_PATH_RE.match(path)
    if path.startswith("attestations/"):
        if not m_active:
            report.error(path, "active declarations must be named attestations/<slug>.yaml")
        elif m_active.group(1) != slug:
            report.error(path, f"agent.slug {slug!r} must equal the filename stem {m_active.group(1)!r}")
        if state == "revoked":
            report.error(path, "a revoked declaration must live under revocations/<slug>.<YYYY-MM-DD>.yaml")
        if "revocation" in rec.doc:
            report.error(path, "active declarations must not carry a revocation block")
    elif path.startswith("revocations/"):
        if not m_revoked:
            report.error(path, "revocations filename must be revocations/<slug>.<YYYY-MM-DD>[.<n>].yaml")
        elif m_revoked.group(1) != slug:
            report.error(path, f"agent.slug {slug!r} must equal the filename slug {m_revoked.group(1)!r}")
        if state != "revoked":
            report.error(path, "declarations under revocations/ must have lifecycle_state: revoked")

    if slug and not L.SLUG_RE.match(slug):
        report.error(path, f"agent.slug {slug!r} violates the slug grammar")

    adoption = rec.adoption
    att = rec.attestation
    grade = adoption.get("enforcement_grade")
    overlays = adoption.get("overlays") or []
    if state in L.IDENTITY_BOUND_STATES and not rec.fpp_id:
        report.error(path, f"agent.fpp_id is required when lifecycle_state is {state}")
    if state == "accepted":
        if grade == "prompt-only" and "runtime_degraded" not in overlays:
            report.error(path, "accepted + enforcement_grade prompt-only requires overlay runtime_degraded")
        if "verification_failed" in overlays:
            report.error(path, "overlay verification_failed blocks lifecycle_state accepted")
        if grade == "none":
            report.error(path, "enforcement_grade none cannot be declared accepted; stay reviewed")
    if state in ("inherited", "forked", "superseded") and not str(att.get("notes") or "").strip():
        report.error(
            path, f"lifecycle_state {state} requires attestation.notes naming the parent, successor, or new hash"
        )
    if state == "revoked":
        if not str(att.get("reason") or "").strip():
            report.error(path, "revoked declarations require a non-empty attestation.reason")
        rev = rec.doc.get("revocation") or {}
        pred = rec.predecessor or {}
        if (
            isinstance(rev, dict)
            and rev.get("original_path")
            and pred.get("path")
            and rev["original_path"] != pred["path"]
        ):
            report.error(path, "revocation.original_path must equal predecessor_record.path")

    # transition and action
    tr = rec.transition
    version = rec.version
    action = rec.action
    t_from, t_to = tr.get("from"), tr.get("to")
    if t_to != state:
        report.error(path, f"adoption.transition.to {t_to!r} must equal lifecycle_state {state!r}")
    if version == 1:
        if action != "attest":
            report.error(path, f"attestation.action must be 'attest' for version 1, got {action!r}")
        if rec.predecessor is not None or tr.get("predecessor_ref") is not None:
            report.error(path, "version 1 must not reference a predecessor")
        if t_from is None:
            if state not in L.INITIAL_STATES:
                report.error(
                    path,
                    f"adoption.transition: an initial declaration may be reviewed or inherited, not {state!r}; "
                    "a first accepted filing must record transition.from: reviewed with structured evidence",
                )
        elif t_from == "reviewed":
            if (t_from, state) not in L.ALLOWED_TRANSITIONS and t_from != state:
                report.error(path, f"adoption.transition: {t_from} -> {state} is not an allowed edge")
            if not isinstance((adoption.get("evidence") or {}).get("inspection"), dict):
                report.error(
                    path, "adoption.evidence.inspection is required when transition.from is reviewed off-ledger"
                )
        else:
            report.error(path, f"adoption.transition.from {t_from!r} is not valid for a version 1 declaration")
    else:
        if action == "attest":
            report.error(path, "attestation.action attest is only valid for version 1")
        if rec.predecessor is None:
            report.error(path, "versions after 1 require attestation.predecessor_record")
        elif tr.get("predecessor_ref") != rec.predecessor.get("path"):
            report.error(path, "adoption.transition.predecessor_ref must equal predecessor_record.path")
        if action == "withdraw-adoption" and state != "revoked":
            report.error(path, "attestation.action withdraw-adoption requires lifecycle_state revoked")
        if state == "revoked" and action != "withdraw-adoption":
            report.error(path, "lifecycle_state revoked requires attestation.action withdraw-adoption")
        if action == "re-adopt" and t_from != "revoked":
            report.error(path, "attestation.action re-adopt requires transition.from revoked")
        if t_from == "revoked" and action != "re-adopt":
            report.error(path, "transition.from revoked requires attestation.action re-adopt")
        if t_from is not None and t_to is not None and t_from != t_to and (t_from, t_to) not in L.ALLOWED_TRANSITIONS:
            report.error(path, f"adoption.transition: {t_from} -> {t_to} is not an allowed edge")
        if t_from == t_to and action not in ("amend", "correct-declaration"):
            report.error(path, f"attestation.action {action} requires a lifecycle change")

    # structured first-acceptance evidence
    if state == "accepted" and t_from != "accepted":
        ev = adoption.get("evidence") or {}
        insp = ev.get("inspection") if isinstance(ev, dict) else None
        acc = ev.get("acceptance") if isinstance(ev, dict) else None
        if not isinstance(insp, dict) or not isinstance(acc, dict):
            report.error(
                path,
                "a declaration entering accepted requires structured adoption.evidence.inspection and "
                "adoption.evidence.acceptance; attestation.notes is never evidence",
            )
        else:
            const_hash = adoption.get("constitution_hash")
            for label, item in (("inspection", insp), ("acceptance", acc)):
                if item.get("constitution_hash") != const_hash:
                    report.error(
                        path, f"adoption.evidence.{label}.constitution_hash must equal adoption.constitution_hash"
                    )
            try:
                inspected = L.parse_iso(str(insp.get("inspected_at")))
                accepted = L.parse_iso(str(acc.get("accepted_at")))
                occurred = L.parse_iso(str(tr.get("occurred_at")))
            except ValueError:
                report.error(path, "adoption.evidence timestamps must be ISO 8601 date-times")
            else:
                if inspected > accepted:
                    report.error(path, "adoption.evidence: inspected_at must not postdate accepted_at")
                if accepted > occurred:
                    report.error(path, "adoption.evidence: accepted_at must not postdate transition.occurred_at")

    # provenance
    authorship = rec.authorship
    actor = tr.get("actor") or {}
    if isinstance(actor, dict) and actor.get("type"):
        expected_type = "agent" if authorship == "agent-signed" else "operator"
        if actor.get("type") != expected_type:
            report.error(
                path, f"adoption.transition.actor.type must be {expected_type!r} for {authorship} declarations"
            )
    pubkey = rec.public_key_hex
    fpp_id = rec.fpp_id
    if pubkey:
        m = L.FPP_ID_RE.match(fpp_id or "")
        if not m:
            report.error(path, "agent.public_key_hex is set but agent.fpp_id is not a v2 identifier")
        else:
            try:
                fp = L.fingerprint_public_key(pubkey)
            except ValueError:
                fp = ""
            if fp != m.group(1):
                report.error(path, "agent.public_key_hex does not fingerprint to agent.fpp_id")
    if authorship == "agent-signed":
        sig = att.get("signature")
        if not fpp_id:
            report.error(path, "agent-signed declarations require agent.fpp_id")
        if not pubkey:
            report.error(path, "agent-signed declarations require agent.public_key_hex")
        if not sig:
            report.error(path, "agent-signed declarations require attestation.signature over the canonical payload")
        elif pubkey and isinstance(sig, str):
            if not L.verify_ed25519(pubkey, sig, L.canonical_payload(rec.doc)):
                report.error(
                    path, "attestation.signature does not verify over the canonical payload with agent.public_key_hex"
                )
        if (
            att.get("filing") != "self"
            and actor.get("type") == "agent"
            and att.get("filing") not in ("self", "operator")
        ):
            report.error(path, "attestation.filing must be self or operator")
    elif authorship == "operator-reported":
        if att.get("filing") == "self":
            report.error(path, "attestation.filing self is valid only with authorship agent-signed")
        if att.get("signature"):
            report.error(
                path, "operator-reported declarations must not carry an agent signature; file a signed correction"
            )

    # public URLs
    runtime = rec.doc.get("runtime")
    if isinstance(runtime, dict):
        for key in ("a2a_endpoint", "agent_card_url"):
            url = runtime.get(key)
            if isinstance(url, str) and not L.is_public_url(url):
                report.error(
                    path, f"runtime.{key} must be a public URL (no RFC1918, link-local, loopback, or localhost)"
                )


Report = L.Report


# --------------------------------------------------------------------------- tree model


@dataclass
class Lineage:
    declaration_id: str
    records: list[L.Record] = field(default_factory=list)
    head: L.Record | None = None
    chain: list[L.Record] = field(default_factory=list)  # head first, back to version 1 (resolved)


class Tree:
    def __init__(
        self,
        root: Path,
        records: list[L.Record],
        chains: dict[tuple[str, str], L.Chain],
        git: L.Git,
        mode: str,
        report: Report,
    ) -> None:
        self.root = root
        self.records = records
        self.by_path = {r.path: r for r in records}
        self.chains = chains
        self.git = git
        self.mode = mode
        self.report = report
        self.head_sha = git.head() if git.available and git.has_commits() else None
        self.lineages: dict[str, Lineage] = {}

    # -- lineage resolution -------------------------------------------------
    def resolve_predecessor(self, rec: L.Record) -> L.Record | None:
        pred = rec.predecessor
        if not pred or not isinstance(pred.get("path"), str) or not isinstance(pred.get("sha256"), str):
            return None
        path, sha = pred["path"], pred["sha256"]
        in_tree = self.by_path.get(path)
        if in_tree is not None and in_tree.sha256 == sha:
            return in_tree
        if self.head_sha:
            blob = self.git.find_blob(path, sha, self.head_sha)
            if blob is not None:
                hist = L.parse_record(path, blob)
                if hist is not None:
                    hist.historical = True
                    return hist
        if self.mode == "working":
            self.report.note(
                f"{rec.path}: predecessor {path}@{sha[:12]} not present in the working tree; "
                "history checks require a release mode"
            )
            return None
        self.report.error(
            rec.path, f"predecessor_record {path}@{sha[:12]} was not found in the tree or in reachable Git history"
        )
        return None

    def check_link(self, rec: L.Record, pred: L.Record) -> None:
        path = rec.path
        if pred.declaration_id != rec.declaration_id:
            self.report.error(
                path,
                f"predecessor_record {pred.path} belongs to lineage {pred.declaration_id}; "
                "declaration_id is immutable and a competing claim needs a new lineage",
            )
        if pred.version != rec.version - 1:
            self.report.error(
                path, f"version {rec.version} must follow predecessor version {pred.version} by exactly one"
            )
        if rec.transition.get("from") != pred.state:
            self.report.error(
                path,
                f"adoption.transition.from {rec.transition.get('from')!r} must equal the predecessor "
                f"lifecycle_state {pred.state!r}",
            )
        if pred.slug != rec.slug:
            self.report.error(
                path, f"agent.slug changed from {pred.slug!r} to {rec.slug!r}; slug is immutable within a lineage"
            )
        action = rec.action
        immutable = [
            ("agent.fpp_id", pred.fpp_id, rec.fpp_id),
            ("agent.public_key_hex", pred.public_key_hex, rec.public_key_hex),
            ("attestation.authorship", pred.authorship, rec.authorship),
            ("attestation.filing", pred.attestation.get("filing"), rec.attestation.get("filing")),
            ("operator.name", pred.operator.get("name"), rec.operator.get("name")),
            ("operator.contact", pred.contact, rec.contact),
        ]
        if action == "correct-declaration":
            if pred.fpp_id and rec.fpp_id != pred.fpp_id:
                self.report.error(
                    path, "correct-declaration may not change an existing agent.fpp_id; a rotated key is a new lineage"
                )
            if pred.authorship == "agent-signed" and rec.authorship != "agent-signed":
                self.report.error(
                    path, "correct-declaration may not downgrade attestation.authorship from agent-signed"
                )
            if not pred.is_active_path:
                self.report.error(path, "correct-declaration must follow an active predecessor")
        else:
            for label, before, after in immutable:
                if before != after:
                    self.report.error(
                        path,
                        f"{action} may not change {label} ({before!r} -> {after!r}); "
                        "identity and provenance changes require correct-declaration or a new lineage",
                    )
        if action == "amend" and not pred.is_active_path:
            self.report.error(path, "amend must follow an active predecessor under attestations/")
        if action == "withdraw-adoption" and not pred.is_active_path:
            self.report.error(path, "withdraw-adoption must follow an active predecessor under attestations/")
        if action == "re-adopt":
            if pred.is_active_path or pred.state != "revoked":
                self.report.error(path, "re-adopt must follow a revoked predecessor under revocations/")
            if not rec.is_active_path:
                self.report.error(path, "re-adopt must recreate attestations/<slug>.yaml")

    def build_lineages(self) -> None:
        for rec in self.records:
            if not rec.declaration_id:
                continue
            self.lineages.setdefault(rec.declaration_id, Lineage(rec.declaration_id)).records.append(rec)
        for lineage in self.lineages.values():
            by_version: dict[int, list[L.Record]] = {}
            for r in lineage.records:
                by_version.setdefault(r.version, []).append(r)
            for v, recs in by_version.items():
                if len(recs) > 1:
                    paths = ", ".join(r.path for r in recs)
                    self.report.error(
                        recs[0].path, f"lineage {lineage.declaration_id} has duplicate version {v}: {paths}"
                    )
            head = max(lineage.records, key=lambda r: r.version)
            lineage.head = head
            chain = [head]
            seen: set[str] = set()
            current = head
            while current.version > 1 and current.predecessor:
                key = f"{current.predecessor.get('path')}@{current.predecessor.get('sha256')}"
                if key in seen:
                    self.report.error(current.path, "predecessor chain loops")
                    break
                seen.add(key)
                pred = self.resolve_predecessor(current)
                if pred is None:
                    break
                self.check_link(current, pred)
                chain.append(pred)
                current = pred
            lineage.chain = chain
            chain_keys = {(r.path, r.sha256) for r in chain}
            for r in lineage.records:
                if (r.path, r.sha256) not in chain_keys:
                    self.report.error(
                        r.path,
                        f"version {r.version} is not part of lineage {lineage.declaration_id} head "
                        f"{head.path} (version {head.version}); orphan versions are not allowed",
                    )
                elif r is not head and r.is_active_path:
                    self.report.error(r.path, "only the lineage head may be an active declaration")

    # -- occupancy ------------------------------------------------------------
    def chain_for(self, rec: L.Record) -> L.Chain | None:
        return self.chains.get((rec.slug or "", rec.sha256))

    def admission_status(self, rec: L.Record) -> str | None:
        chain = self.chain_for(rec)
        return chain.status if chain else None

    def holders(self) -> dict[str, list[L.Record]]:
        """slug -> lineage heads that currently hold or reserve it."""
        held: dict[str, list[L.Record]] = {}
        for lineage in self.lineages.values():
            head = lineage.head
            if head is None or not head.slug:
                continue
            chain = self.chain_for(head)
            if chain is not None and chain.slug_released:
                continue
            held.setdefault(head.slug, []).append(head)
        return held

    def check_occupancy(self) -> None:
        active = [r for r in self.records if r.is_active_path]
        by_slug: dict[str, list[L.Record]] = {}
        for r in active:
            if r.slug:
                by_slug.setdefault(r.slug, []).append(r)
        for slug, recs in by_slug.items():
            if len(recs) > 1:
                paths = sorted(r.path for r in recs)
                for r in recs:
                    others = ", ".join(p for p in paths if p != r.path)
                    self.report.error(r.path, f"slug {slug!r} is also held by {others}; active slugs must be unique")

        heads = [ln.head for ln in self.lineages.values() if ln.head is not None]
        active_heads = [h for h in heads if h.is_active_path]
        by_fpp: dict[str, list[L.Record]] = {}
        for h in active_heads:
            if h.authorship == "agent-signed" and h.fpp_id:
                by_fpp.setdefault(h.fpp_id, []).append(h)
        for fpp_id, recs in by_fpp.items():
            if len({r.declaration_id for r in recs}) > 1:
                paths = sorted(r.path for r in recs)
                for r in recs:
                    others = ", ".join(p for p in paths if p != r.path)
                    self.report.error(
                        r.path,
                        f"authenticated fpp_id {fpp_id} is also held by {others}; "
                        "an authenticated identity may hold only one active declaration",
                    )

        held = self.holders()
        taken = set(held.keys()) | set(by_slug.keys())
        for rec in active_heads:
            slug = rec.slug or ""
            preferred = L.slugify(rec.name)
            other_holders = [h for h in held.get(slug, []) if h.declaration_id != rec.declaration_id]
            for h in other_holders:
                if h.is_active_path:
                    continue  # reported by the uniqueness rule above
                self.report.error(
                    rec.path,
                    f"slug {slug!r} is reserved by {h.path} (lineage {h.declaration_id}, "
                    f"{h.describe_identity()}); a steward slug-release event on that record's "
                    "admission chain is required before another lineage may take it",
                )
            if slug == preferred or slug.startswith(preferred + "--") or not preferred:
                continue
            pref_holders = [
                h
                for h in held.get(preferred, [])
                if h.declaration_id != rec.declaration_id and h.identity_key() != rec.identity_key()
            ]
            if pref_holders:
                holder = pref_holders[0]
                suggestion = suggest_slug(preferred, rec, taken)
                self.report.error(
                    rec.path,
                    f"slug {preferred!r} is held by {holder.path} ({holder.describe_identity()}); "
                    f"a homonym must use a '--' qualifier. Use {suggestion}",
                )

    # -- summary ---------------------------------------------------------------
    def summary_lines(self) -> list[str]:
        lines = ["lineage heads:"]
        counts = {"agent-signed": 0, "operator-reported": 0}
        for lineage in sorted(self.lineages.values(), key=lambda ln: ln.head.path if ln.head else ""):
            head = lineage.head
            if head is None:
                continue
            status = self.admission_status(head) or "none"
            lines.append(
                f"  {head.path}  lineage {head.declaration_id}  version {head.version}  "
                f"lifecycle {head.state}  {head.authorship}  admission {status}"
            )
            if status == "admitted" and head.authorship in counts:
                counts[head.authorship] += 1
        total = counts["agent-signed"] + counts["operator-reported"]
        lines.append(
            f"currently admitted declarations: {total} "
            f"(agent-signed: {counts['agent-signed']}, operator-reported: {counts['operator-reported']})"
        )
        lines.append("evidence ceiling: declaration-only; admission is not agent consent or behavioral compliance")
        return lines


def suggest_slug(preferred: str, rec: L.Record, taken: set[str]) -> str:
    candidates: list[str] = []
    cslug = L.contact_slug(rec.contact)
    if cslug:
        candidates.append(f"{preferred}--{cslug}")
    m = L.FPP_ID_RE.match(rec.fpp_id or "")
    if m:
        candidates.append(f"{preferred}--{m.group(1)[:8]}")
    date = str(rec.adoption.get("date") or "").replace("-", "")
    if cslug and date:
        candidates.append(f"{preferred}--{cslug}-{date}")
    for c in candidates:
        if c not in taken:
            return c
    return candidates[-1] if candidates else f"{preferred}--<qualifier>"


# --------------------------------------------------------------------------- diff and history rules


def protected_intake_path(path: str) -> bool:
    return (
        path.endswith(".asc")
        or path in L.INTAKE_PROTECTED_FILES
        or any(path.startswith(p) for p in L.INTAKE_PROTECTED_PREFIXES)
    )


def is_declaration_path(path: str) -> bool:
    return (path.startswith("attestations/") or path.startswith("revocations/")) and path.endswith(".yaml")


def check_declaration_changes(tree: Tree, base: str, changes: list[tuple[str, str]], report: Report) -> list[L.Record]:
    """Shared intake/admission rules for how declaration files may change relative to base."""
    git = tree.git
    added_or_modified: list[L.Record] = []
    change_map = {p: s for s, p in changes}
    replaced: dict[str, L.Record] = {}
    for rec in tree.records:
        if rec.predecessor and rec.path in change_map and change_map[rec.path] in ("A", "M"):
            replaced[f"{rec.predecessor.get('path')}@{rec.predecessor.get('sha256')}"] = rec
    for status, path in changes:
        if not is_declaration_path(path):
            continue
        base_blob = git.show(base, path) if status in ("M", "D") else None
        base_key = f"{path}@{L.sha256_bytes(base_blob)}" if base_blob is not None else None
        if path.startswith("revocations/"):
            if status != "A":
                report.error(
                    path, "revocations/ is append-only; existing withdrawal records may not be modified or deleted"
                )
                continue
        if status == "D":
            if base_key not in replaced:
                report.error(
                    path,
                    "deleted without an authorized replacement; a declaration may disappear from "
                    "attestations/ only through a predecessor-linked withdraw-adoption record",
                )
            continue
        rec_opt = tree.by_path.get(path)
        if rec_opt is None:
            continue
        rec = rec_opt
        added_or_modified.append(rec)
        if status == "M" and base_blob is not None:
            base_rec = L.parse_record(path, base_blob)
            if base_rec is None:
                report.error(path, "base version could not be parsed")
                continue
            pred = rec.predecessor or {}
            if rec.declaration_id != base_rec.declaration_id:
                suggestion = suggest_slug(L.slugify(rec.name), rec, set(tree.holders().keys()))
                report.error(
                    path,
                    f"replaces lineage {base_rec.declaration_id} held by {path} ({base_rec.describe_identity()}) "
                    f"with a different declaration_id; the slug {base_rec.slug!r} is held by {path}. "
                    f"Use {suggestion}",
                )
                continue
            if rec.version != base_rec.version + 1:
                report.error(
                    path,
                    f"modified in place: version must increase from {base_rec.version} to "
                    f"{base_rec.version + 1}, got {rec.version}",
                )
            if pred.get("path") != path or pred.get("sha256") != L.sha256_bytes(base_blob):
                report.error(path, "predecessor_record must name this path and the SHA-256 of the exact base bytes")
        elif status == "A" and path.startswith("revocations/"):
            pred = rec.predecessor or {}
            pred_path = str(pred.get("path") or "")
            if change_map.get(pred_path) != "D":
                report.error(
                    path, f"withdraw-adoption must remove {pred_path or 'the active record'} in the same change"
                )
            else:
                prev = git.show(base, pred_path)
                if prev is None or L.sha256_bytes(prev) != pred.get("sha256"):
                    report.error(
                        path, "predecessor_record.sha256 does not match the base bytes of the withdrawn active record"
                    )
    return added_or_modified


def check_intake_diff(tree: Tree, base: str, context: L.Context, report: Report) -> None:
    git = tree.git
    head = git.head()
    merge_base = git.merge_base(base, head)
    if merge_base is None:
        raise L.FailClosed("no merge base between --base-ref and HEAD")
    changes = git.diff_name_status(merge_base, head)
    for _status, path in changes:
        if path.startswith("admissions/"):
            report.error(path, "intake PRs may not add, modify, or delete anything under admissions/ (steward-only)")
        elif path.endswith(".asc"):
            report.error(path, "intake PRs may not add or modify OpenPGP signatures or certificates (steward-only)")
        elif protected_intake_path(path):
            report.error(
                path, "intake PRs may not change protected paths (stewards/, schema/, scripts/, .github/, tests/, pins)"
            )
    changed = check_declaration_changes(tree, merge_base, changes, report)
    for rec in changed:
        check_filing_authority(tree, merge_base, rec, context, report)


def check_filing_authority(tree: Tree, base: str, rec: L.Record, context: L.Context, report: Report) -> None:
    """Operator-reported filings need GitHub authority (or steward transport); agent-signed ones need the signature."""
    git = tree.git
    authority_rec: L.Record = rec
    if rec.version > 1 and rec.predecessor:
        pred_path = str(rec.predecessor.get("path") or "")
        blob = git.show(base, pred_path)
        pred = L.parse_record(pred_path, blob) if blob is not None else tree.by_path.get(pred_path)
        if pred is None:
            hist = git.find_blob(pred_path, str(rec.predecessor.get("sha256")), git.head())
            pred = L.parse_record(pred_path, hist) if hist is not None else None
        if pred is not None:
            authority_rec = pred
            if (
                rec.action == "correct-declaration"
                and rec.authorship == "agent-signed"
                and pred.fpp_id
                and pred.fpp_id == rec.fpp_id
            ):
                # The lineage already named this key; the key holder's signature authorizes the upgrade.
                return
    if authority_rec.authorship == "agent-signed":
        return  # the canonical-payload signature is the authority and is checked per record
    contact = authority_rec.contact
    what = f"operator authority for {authority_rec.path}" if authority_rec is not rec else "operator authority"
    m = L.GITHUB_CONTACT_RE.match(contact)
    if m:
        L.github_authority_ok(context, m.group(1), report, rec.path, what)
    elif contact.lower().startswith("github:"):
        report.error(rec.path, f"operator.contact {contact!r} must be github:<lowercase-login> for GitHub intake")
    else:
        L.steward_transport_ok(context, tree.root, report, rec.path)


def check_admission_diff(tree: Tree, base: str, report: Report) -> None:
    git = tree.git
    head = git.head()
    if not git.is_ancestor(base, head):
        report.error(
            None,
            f"current main {base[:12]} is not an ancestor of the candidate head {head[:12]}; "
            "admission requires a fast-forward candidate built from current main",
        )
        return
    changes = git.diff_name_status(base, head)
    for status, path in changes:
        if path.startswith("admissions/") and status != "A":
            report.error(path, "admissions/ is append-only; existing signatures and events may not change")
    changed = check_declaration_changes(tree, base, changes, report)
    change_map = {p: s for s, p in changes}
    for rec in changed:
        slug, sha = rec.slug or "", rec.sha256
        sig = f"admissions/{slug}.{sha}.record.asc"
        if not (tree.root / sig).exists():
            report.error(
                rec.path, f"missing {sig}: every admitted declaration version needs a steward signature over its bytes"
            )
        chain = tree.chains.get((slug, sha))
        first = f"admissions/{slug}.{sha}.0001.json"
        if chain is None or chain.events[0].sequence != 1:
            report.error(rec.path, f"missing {first}: every admitted declaration version needs an admit event")
        else:
            ev = chain.events[0]
            review = ev.doc.get("review") or {}
            hashes = review.get("declarationHashes") if isinstance(review, dict) else None
            if not isinstance(hashes, dict) or hashes.get(rec.path) != sha:
                report.error(ev.path, f"review.declarationHashes must bind {rec.path} to {sha}")
            if ev.doc.get("declarationAction") != rec.action:
                report.error(
                    ev.path,
                    f"declarationAction {ev.doc.get('declarationAction')!r} does not match "
                    f"attestation.action {rec.action!r}",
                )
            if change_map.get(ev.path) != "A":
                report.error(ev.path, "admit event for a changed declaration must be introduced by this admission")
    for (_slug, sha), chain in tree.chains.items():
        for ev in chain.events:
            if change_map.get(ev.path) != "A" or ev.sequence == 1:
                continue
            record_path = str((ev.doc.get("record") or {}).get("path") or "")
            if record_path in change_map:
                new_rec = tree.by_path.get(record_path)
                pred_sha = (new_rec.predecessor or {}).get("sha256") if new_rec else None
                if ev.action == "correct-admission" and new_rec is not None and pred_sha == sha:
                    continue
                report.error(
                    ev.path,
                    f"admission-only action {ev.action} arrives with a change to {record_path}; steward "
                    "actions must preserve declaration bytes and lifecycle_state",
                )


def check_main_history(tree: Tree, report: Report) -> None:
    git = tree.git
    if git.is_shallow():
        # A shallow boundary commit looks like a parentless root, so the walk below would silently skip
        # every rewrite that happened before the cut. Only a complete first-parent history is evidence.
        raise L.FailClosed("main mode append-only history check requires a non-shallow repository")
    head = git.head()
    for commit in git.first_parent_chain(head):
        parent = git.parent(commit)
        if parent is None:
            continue
        changes = git.diff_name_status(parent, commit)
        added_records: dict[str, L.Record] = {}
        for status, path in changes:
            if status in ("A", "M") and is_declaration_path(path):
                blob = git.show(commit, path)
                rec = L.parse_record(path, blob) if blob is not None else None
                if rec is not None and rec.predecessor:
                    added_records[f"{rec.predecessor.get('path')}@{rec.predecessor.get('sha256')}"] = rec
        for status, path in changes:
            if path.startswith("admissions/") and status != "A":
                report.error(
                    path,
                    f"commit {commit[:12]} {'modified' if status == 'M' else 'deleted'} an admission artifact; "
                    "admissions/ is append-only",
                )
            elif path.startswith("revocations/") and status != "A":
                report.error(
                    path, f"commit {commit[:12]} rewrote or deleted a withdrawal record; revocations/ is append-only"
                )
            elif path.startswith("attestations/") and path.endswith(".yaml") and status in ("M", "D"):
                before = git.show(parent, path)
                key = f"{path}@{L.sha256_bytes(before)}" if before is not None else None
                if key not in added_records:
                    verb = "deleted" if status == "D" else "rewrote in place"
                    report.error(
                        path,
                        f"commit {commit[:12]} {verb} an active declaration without a predecessor-linked "
                        "replacement version",
                    )


# --------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("working", *RELEASE_MODES), required=True)
    ap.add_argument("--schema", default="schema/attestation.schema.json")
    ap.add_argument("--event-schema", default="schema/admission-event.schema.json")
    ap.add_argument("--all", action="store_true", help="validate the whole tree (required)")
    ap.add_argument("--root", default=".")
    ap.add_argument("--base-ref", help="immutable base commit for intake/admission modes")
    ap.add_argument("--context", help="trusted GitHub event context JSON written by the workflow")
    ap.add_argument("--summary", action="store_true", help="print lineage heads and provenance-split admitted counts")
    ap.add_argument("--gpg", help="path to the gpg binary (default: LEDGER_GPG or auto-detect)")
    args = ap.parse_args(argv)
    if not args.all:
        print("FAIL --all is required: the ledger is validated as a whole tree", file=sys.stderr)
        return L.EXIT_FAIL_CLOSED

    root = Path(args.root).resolve()
    report = Report()
    try:
        git = L.Git(root)
        context = L.load_context(args.context)
        base = L.require_release_inputs(args.mode, git, args.base_ref, context)
        gpg = L.Gpg(L.find_gpg(args.gpg))
        schema_path = root / args.schema if not Path(args.schema).is_absolute() else Path(args.schema)
        if not schema_path.exists():
            raise L.FailClosed(f"schema {args.schema} not found")
        validator = L.load_schema(schema_path)
        event_schema_path = root / args.event_schema
        event_validator = L.load_schema(event_schema_path) if event_schema_path.exists() else None

        files = list(L.iter_tree_files(root))
        L.scan_secret_armor(root, files, report)
        L.check_cert_pins(gpg, root, report)
        L.check_mode_context(args.mode, context, root, report)

        records: list[L.Record] = []
        for rel in files:
            if is_declaration_path(rel):
                rec = L.parse_record(rel, (root / rel).read_bytes(), report)
                if rec is not None:
                    records.append(rec)
            elif (rel.startswith("attestations/") or rel.startswith("revocations/")) and rel.rsplit("/", 1)[
                -1
            ] != ".gitkeep":
                report.error(rel, "only <slug>.yaml declarations may live under attestations/ and revocations/")
        for rec in records:
            check_record(rec, validator, report)

        chains = L.load_chains(root, report)
        for chain in chains.values():
            if event_validator is not None:
                for ev in chain.events:
                    for msg in L.schema_errors(event_validator, ev.doc):
                        report.error(ev.path, f"schema: {msg}")
            L.check_chain_structure(chain, root, report)

        tree = Tree(root, records, chains, git, args.mode, report)
        tree.build_lineages()
        tree.check_occupancy()

        if args.mode == "intake":
            assert base is not None and context is not None
            check_intake_diff(tree, base, context, report)
        elif args.mode == "admission":
            assert base is not None
            check_admission_diff(tree, base, report)
        elif args.mode == "main":
            check_main_history(tree, report)

        if args.summary:
            for line in tree.summary_lines():
                print(line)
    except L.FailClosed as exc:
        report.emit()
        print(f"FAIL (closed) {exc}", file=sys.stderr)
        return L.EXIT_FAIL_CLOSED

    report.emit()
    if report.ok:
        print(
            f"OK mode={args.mode}: {len(records)} declaration(s), {len(chains)} admission chain(s); "
            "all records are declaration-only"
        )
        return L.EXIT_OK
    print(f"{len(report.errors)} error(s)", file=sys.stderr)
    return L.EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
