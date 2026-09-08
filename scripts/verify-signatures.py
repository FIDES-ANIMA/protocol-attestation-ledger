#!/usr/bin/env python3
"""Verify FIDES-ANIMA steward signatures and admission chains for the FPP attestation ledger.

Modes:
  intake     contributor PR: pins only; any added or changed signature/admission artifact is rejected
  admission  steward admission/* branch: every artifact introduced by the candidate must verify against
             the pinned signing subkey, the HEAD commit must be steward-signed, admissions/ is append-only
  main       published tree: every admission chain, record signature, event signature, and correction link
             must verify against the committed certificate; artifacts signed by a since-expired subkey are
             accepted only with a diagnostic and only when made while that subkey was valid

GnuPG only ever runs inside a throwaway GNUPGHOME that is deleted before exit; the ambient keyring is
never read. Nothing here requires or touches a secret key.

Exit codes: 0 valid, 1 invalid, 2 fail-closed (inputs, history, or gpg unavailable).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledgerlib as L  # noqa: E402

Report = L.Report


@dataclass
class ResolvedRecord:
    record: L.Record
    in_tree: bool


@dataclass
class Verifier:
    root: Path
    git: L.Git
    gpg: L.Gpg
    cert: L.CertInfo
    primary_pin: str
    subkey_pin: str
    report: Report
    chains: dict[tuple[str, str], L.Chain]
    tree_records: dict[str, L.Record]
    new_artifacts: set[str] = field(default_factory=set)  # paths introduced by an admission candidate
    resolved: dict[tuple[str, str], ResolvedRecord | None] = field(default_factory=dict)

    # -- record resolution --------------------------------------------------
    def resolve(self, chain: L.Chain) -> ResolvedRecord | None:
        key = (chain.slug, chain.record_sha)
        if key in self.resolved:
            return self.resolved[key]
        first = chain.events[0]
        record_path = str((first.doc.get("record") or {}).get("path") or "")
        found: ResolvedRecord | None = None
        for rec in self.tree_records.values():
            if rec.sha256 == chain.record_sha and rec.slug == chain.slug:
                found = ResolvedRecord(rec, in_tree=True)
                break
        if found is None and record_path and self.git.available and self.git.has_commits():
            blob = self.git.find_blob(record_path, chain.record_sha, self.git.head())
            if blob is not None:
                hist = L.parse_record(record_path, blob)
                if hist is not None:
                    hist.historical = True
                    found = ResolvedRecord(hist, in_tree=False)
        if found is None:
            self.report.error(
                first.path,
                f"admission chain for record {chain.record_sha[:12]} names {record_path or '?'} "
                "but no declaration with those exact bytes exists in the tree or in history",
            )
        elif found.record.slug != chain.slug:
            self.report.error(first.path, f"chain slug {chain.slug!r} does not match record slug {found.record.slug!r}")
        self.resolved[key] = found
        return found

    # -- signatures ----------------------------------------------------------
    def check_signature(self, env: dict[str, str], sig_rel: str, data: Path, what: str) -> L.SigResult | None:
        sig_path = self.root / sig_rel
        if not sig_path.exists():
            self.report.error(sig_rel, f"missing steward signature for {what}")
            return None
        res = self.gpg.verify_detached(env, sig_path, data)
        if not res.good:
            self.report.error(sig_rel, f"signature over {what} does not verify: {res.detail}")
            return None
        if res.primary_fingerprint != self.primary_pin:
            self.report.error(
                sig_rel,
                f"signature was made under primary key {res.primary_fingerprint}, "
                f"not the pinned steward certificate {self.primary_pin}",
            )
            return None
        signer = res.key_fingerprint or ""
        sub = self.cert.subkeys.get(signer)
        if signer != self.primary_pin and sub is None:
            self.report.error(sig_rel, f"signing key {signer} is not part of the committed certificate")
            return None
        if signer == self.subkey_pin:
            return res
        # Signed by a key other than the pinned signing subkey.
        state = "expired" if (res.key_expired or (sub is not None and not sub.usable_now)) else "non-pinned"
        if sig_rel in self.new_artifacts:
            self.report.error(
                sig_rel,
                f"new artifact signed by {state} subkey {signer}; admission artifacts must be signed "
                f"by the pinned signing subkey {self.subkey_pin} (see {L.SUBKEY_REF_PATH})",
            )
            return None
        if sub is not None and res.sig_time is not None:
            if sub.expires is not None and res.sig_time > sub.expires:
                self.report.error(
                    sig_rel,
                    f"signature dated after subkey {signer} expired; historical acceptance requires "
                    "a signature made while the subkey was valid",
                )
                return None
            if res.sig_time < sub.created:
                self.report.error(sig_rel, f"signature predates the creation of subkey {signer}")
                return None
        self.report.note(
            f"{sig_rel}: historical artifact signed by {state} subkey {signer} "
            f"(current pinned signing subkey is {self.subkey_pin}); accepted as history, not as new authority"
        )
        return res

    def check_actor(self, ev: L.Event, res: L.SigResult | None) -> None:
        actor = ev.doc.get("actor") or {}
        key_ref = str(actor.get("keyRef") or "")
        if key_ref != f"openpgp:{self.primary_pin}":
            self.report.error(
                ev.path, f"actor.keyRef {key_ref!r} must be the pinned steward primary openpgp:{self.primary_pin}"
            )
        sub_ref = str(actor.get("signingSubkeyRef") or "")
        sub_fpr = sub_ref.removeprefix("openpgp:")
        if sub_fpr not in self.cert.subkeys or "s" not in self.cert.subkeys[sub_fpr].capabilities:
            self.report.error(
                ev.path, f"actor.signingSubkeyRef {sub_ref!r} is not a signing subkey of the committed certificate"
            )
        elif res is not None and res.key_fingerprint and res.key_fingerprint != sub_fpr:
            msg = (
                f"actor.signingSubkeyRef {sub_fpr} differs from the subkey that actually signed the event "
                f"{res.key_fingerprint}"
            )
            if ev.path in self.new_artifacts:
                self.report.error(ev.path, msg)
            else:
                self.report.note(f"{ev.path}: {msg}")

    # -- chains ----------------------------------------------------------------
    def check_chain(self, env: dict[str, str], chain: L.Chain) -> None:
        resolved = self.resolve(chain)
        first = chain.events[0]
        record_sig = f"admissions/{chain.slug}.{chain.record_sha}.record.asc"
        if resolved is not None:
            rec = resolved.record
            if resolved.in_tree:
                data = self.root / rec.path
            else:
                data = Path(env["GNUPGHOME"]) / f"record-{chain.record_sha}.yaml"
                data.write_bytes(rec.raw)
            self.check_signature(env, record_sig, data, f"declaration bytes {chain.record_sha[:12]} ({rec.path})")
            if first.sequence == 1 and first.action == "admit":
                self.check_admit(first, rec)
            for ev in chain.events:
                record = ev.doc.get("record") or {}
                if record.get("declarationId") != rec.declaration_id or record.get("version") != rec.version:
                    self.report.error(ev.path, "record.declarationId/version do not match the declaration bytes")
                if ev.action == "correct-admission":
                    self.check_correction(ev, rec)
        for ev in chain.events:
            res = self.check_signature(env, ev.path + ".asc", self.root / ev.path, f"admission event {ev.path}")
            self.check_actor(ev, res)

    def check_admit(self, ev: L.Event, rec: L.Record) -> None:
        review = ev.doc.get("review") or {}
        hashes = review.get("declarationHashes") if isinstance(review, dict) else None
        if not isinstance(hashes, dict) or hashes.get(rec.path) != rec.sha256:
            self.report.error(ev.path, f"review.declarationHashes must bind {rec.path} to {rec.sha256}")
        if ev.doc.get("declarationAction") != rec.action:
            self.report.error(
                ev.path,
                f"declarationAction {ev.doc.get('declarationAction')!r} does not match "
                f"attestation.action {rec.action!r}",
            )
        auth = ev.doc.get("authority") or {}
        basis = auth.get("basis")
        if rec.authorship == "agent-signed" and basis != "agent-signature":
            self.report.error(ev.path, "authority.basis must be agent-signature for an agent-signed declaration")
        if rec.authorship == "operator-reported" and basis == "agent-signature":
            self.report.error(
                ev.path, "authority.basis agent-signature is impossible for an operator-reported declaration"
            )

    def check_correction(self, ev: L.Event, old: L.Record) -> None:
        ref = ev.doc.get("correctionRef")
        if not isinstance(ref, dict):
            return  # schema already reported
        path, sha = str(ref.get("path") or ""), str(ref.get("sha256") or "")
        new: L.Record | None = None
        in_tree = self.tree_records.get(path)
        if in_tree is not None and in_tree.sha256 == sha:
            new = in_tree
        elif self.git.available and self.git.has_commits():
            blob = self.git.find_blob(path, sha, self.git.head())
            new = L.parse_record(path, blob) if blob is not None else None
        if new is None:
            self.report.error(ev.path, f"correctionRef names {path}@{sha[:12]} but no such declaration bytes exist")
            return
        pred = new.predecessor or {}
        if pred.get("sha256") != old.sha256 or pred.get("path") != old.path:
            self.report.error(
                ev.path, "correctionRef target does not name this record as its predecessor (reciprocal link broken)"
            )
        if new.declaration_id != old.declaration_id or ref.get("declarationId") != old.declaration_id:
            self.report.error(ev.path, "correctionRef must stay within the same lineage (declarationId)")
        if new.version != old.version + 1 or ref.get("version") != new.version:
            self.report.error(
                ev.path, f"correctionRef.version must be {old.version + 1} and match the corrected record"
            )
        if new.action != "correct-declaration":
            self.report.error(ev.path, "correctionRef target must carry attestation.action correct-declaration")
        adm = ref.get("admissionEvent") or {}
        adm_path = str(adm.get("path") or "")
        adm_file = self.root / adm_path
        if not adm_file.exists():
            self.report.error(ev.path, f"correctionRef.admissionEvent {adm_path} does not exist")
        elif L.sha256_bytes(adm_file.read_bytes()) != adm.get("sha256"):
            self.report.error(ev.path, "correctionRef.admissionEvent.sha256 does not hash the referenced event bytes")
        else:
            expected = f"admissions/{new.slug}.{new.sha256}.0001.json"
            if adm_path != expected:
                self.report.error(ev.path, f"correctionRef.admissionEvent must be {expected}")

    def check_corrections_reciprocal(self) -> None:
        """Every admitted correct-declaration must be mirrored by a correct-admission on its predecessor's chain."""
        for (slug, sha), chain in self.chains.items():
            resolved = self.resolved.get((slug, sha))
            if resolved is None:
                continue
            rec = resolved.record
            if rec.action != "correct-declaration" or not rec.predecessor:
                continue
            pred_sha = str(rec.predecessor.get("sha256") or "")
            pred_chain = self.chains.get((slug, pred_sha))
            corrections = [
                e
                for e in (pred_chain.events if pred_chain else [])
                if e.action == "correct-admission" and (e.doc.get("correctionRef") or {}).get("sha256") == sha
            ]
            if not corrections:
                self.report.error(
                    chain.events[0].path,
                    f"{rec.path} is a correct-declaration but the predecessor chain "
                    f"admissions/{slug}.{pred_sha}.* has no correct-admission event "
                    "pointing at it",
                )

    def check_tree_records_admitted(self) -> None:
        for rec in self.tree_records.values():
            key = (rec.slug or "", rec.sha256)
            sig = f"admissions/{rec.slug}.{rec.sha256}.record.asc"
            if not (self.root / sig).exists():
                self.report.error(
                    rec.path, f"missing {sig}: every published declaration needs a steward signature over its bytes"
                )
            if key not in self.chains:
                self.report.error(
                    rec.path,
                    f"missing admissions/{rec.slug}.{rec.sha256}.0001.json: every published "
                    "declaration needs an admit event",
                )

    def check_orphan_signatures(self) -> None:
        admissions = self.root / "admissions"
        if not admissions.exists():
            return
        for p in sorted(admissions.iterdir()):
            rel = f"admissions/{p.name}"
            if p.suffix != ".asc":
                continue
            if L.RECORD_SIG_RE.match(rel):
                m = L.RECORD_SIG_RE.match(rel)
                assert m is not None
                if (m.group(1), m.group(2)) not in self.chains:
                    self.report.error(rel, "record signature without an admission chain for that record")
            elif rel.endswith(".json.asc"):
                if not (self.root / rel[:-4]).exists():
                    self.report.error(rel, "event signature without its event")
            else:
                self.report.error(rel, "unexpected signature file under admissions/")

    # -- summary -----------------------------------------------------------------
    def summary(self) -> list[str]:
        lines: list[str] = []
        for (slug, sha), chain in sorted(self.chains.items()):
            resolved = self.resolved.get((slug, sha))
            desc = "(record unresolved)"
            if resolved is not None:
                rec = resolved.record
                where = "" if resolved.in_tree else " [historical]"
                desc = f"{rec.path}{where} version {rec.version} lifecycle {rec.state} {rec.authorship}"
            lines.append(f"chain {slug} {sha}: admission {chain.status} after {len(chain.events)} event(s); {desc}")
        lines.append(
            "evidence ceiling: declaration-only; a verified admission chain proves steward publication, "
            "not agent consent or behavioral conformance"
        )
        return lines


# --------------------------------------------------------------------------- diff helpers


def intake_diff_checks(git: L.Git, base: str, report: Report) -> None:
    head = git.head()
    merge_base = git.merge_base(base, head)
    if merge_base is None:
        raise L.FailClosed("no merge base between --base-ref and HEAD")
    for _status, path in git.diff_name_status(merge_base, head):
        if path.startswith("admissions/"):
            report.error(path, "intake PRs may not touch admissions/ (steward-only admission artifacts)")
        elif path.endswith(".asc") or path.startswith("stewards/"):
            report.error(path, "intake PRs may not add or change signatures, certificates, or pins (steward-only)")


def admission_diff_checks(git: L.Git, base: str, report: Report) -> set[str]:
    head = git.head()
    if not git.is_ancestor(base, head):
        report.error(
            None,
            f"current main {base[:12]} is not an ancestor of the candidate head {head[:12]}; "
            "admission requires a fast-forward candidate built from current main",
        )
        return set()
    new: set[str] = set()
    for status, path in git.diff_name_status(base, head):
        if path.startswith("admissions/"):
            if status != "A":
                report.error(
                    path,
                    f"admissions/ is append-only; candidate {'modifies' if status == 'M' else 'deletes'} "
                    "an existing signature or event",
                )
            else:
                new.add(path)
        elif path.startswith("stewards/"):
            report.note(
                f"{path}: steward pin or certificate changed in this candidate; verify the rotation is intended"
            )
    return new


def check_commit_signature(
    git: L.Git, gpg_env: dict[str, str], commit: str, verifier: Verifier, report: Report
) -> None:
    code, raw = git.verify_commit_raw(commit, gpg_env, verifier.gpg.binary)
    res = L.parse_status(raw, code)
    if not res.good:
        report.error(None, f"commit {commit[:12]} is not signed by the committed steward certificate: {res.detail}")
        return
    if res.primary_fingerprint != verifier.primary_pin:
        report.error(
            None, f"commit {commit[:12]} signed under primary {res.primary_fingerprint}, not the pinned certificate"
        )
    elif res.key_fingerprint != verifier.subkey_pin:
        report.error(
            None,
            f"commit {commit[:12]} signed by subkey {res.key_fingerprint}, not the pinned signing subkey "
            f"{verifier.subkey_pin}",
        )


# --------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("intake", "admission", "main"), required=True)
    ap.add_argument("--cert", default=L.CERT_PATH)
    ap.add_argument("--expected-key-ref", default=L.KEY_REF_PATH)
    ap.add_argument("--expected-signing-subkey-ref", default=L.SUBKEY_REF_PATH)
    ap.add_argument("--event-schema", default="schema/admission-event.schema.json")
    ap.add_argument("--root", default=".")
    ap.add_argument("--base-ref", help="immutable base commit for intake/admission modes")
    ap.add_argument("--context", help="trusted GitHub event context JSON written by the workflow")
    ap.add_argument("--gpg", help="path to the gpg binary (default: LEDGER_GPG or auto-detect)")
    ap.add_argument(
        "--require-signed-commits",
        action="store_true",
        help="main mode: additionally require every first-parent commit to be steward-signed",
    )
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    report = Report()
    if (
        L.posix(args.cert) != L.CERT_PATH
        or L.posix(args.expected_key_ref) != L.KEY_REF_PATH
        or L.posix(args.expected_signing_subkey_ref) != L.SUBKEY_REF_PATH
    ):
        print(
            f"FAIL (closed) pins must be the committed files {L.CERT_PATH}, {L.KEY_REF_PATH}, {L.SUBKEY_REF_PATH}",
            file=sys.stderr,
        )
        return L.EXIT_FAIL_CLOSED

    try:
        git = L.Git(root)
        context = L.load_context(args.context)
        base = L.require_release_inputs(args.mode, git, args.base_ref, context)
        gpg = L.Gpg(L.find_gpg(args.gpg))

        files = list(L.iter_tree_files(root))
        L.scan_secret_armor(root, files, report)
        cert = L.check_cert_pins(gpg, root, report)
        L.check_mode_context(args.mode, context, root, report)
        if cert is None:
            raise Invalid()

        if args.mode == "intake":
            assert base is not None
            intake_diff_checks(git, base, report)
            raise Done()

        primary_pin = L.read_pin(root, L.KEY_REF_PATH)
        subkey_pin = L.read_pin(root, L.SUBKEY_REF_PATH)

        event_schema_path = root / args.event_schema
        if not event_schema_path.exists():
            raise L.FailClosed(f"event schema {args.event_schema} not found")
        event_validator = L.load_schema(event_schema_path)

        tree_records: dict[str, L.Record] = {}
        for rel in files:
            if (rel.startswith("attestations/") or rel.startswith("revocations/")) and rel.endswith(".yaml"):
                rec = L.parse_record(rel, (root / rel).read_bytes(), report)
                if rec is not None:
                    tree_records[rel] = rec

        chains = L.load_chains(root, report)
        for chain in chains.values():
            for ev in chain.events:
                for msg in L.schema_errors(event_validator, ev.doc):
                    report.error(ev.path, f"schema: {msg}")
            L.check_chain_structure(chain, root, report)

        verifier = Verifier(
            root=root,
            git=git,
            gpg=gpg,
            cert=cert,
            primary_pin=primary_pin,
            subkey_pin=subkey_pin,
            report=report,
            chains=chains,
            tree_records=tree_records,
        )
        if args.mode == "admission":
            assert base is not None
            verifier.new_artifacts = admission_diff_checks(git, base, report)

        with gpg.ephemeral_home() as env:
            cert_armor = (root / L.CERT_PATH).read_bytes()
            gpg.import_public_cert(env, cert_armor)
            for chain in chains.values():
                verifier.check_chain(env, chain)
            if args.mode == "admission":
                check_commit_signature(git, env, git.head(), verifier, report)
            elif args.require_signed_commits:
                for commit in git.first_parent_chain(git.head()):
                    check_commit_signature(git, env, commit, verifier, report)

        verifier.check_tree_records_admitted()
        verifier.check_orphan_signatures()
        verifier.check_corrections_reciprocal()
        for line in verifier.summary():
            report.note(line)
    except Done:
        pass
    except Invalid:
        pass
    except L.FailClosed as exc:
        report.emit()
        print(f"FAIL (closed) {exc}", file=sys.stderr)
        return L.EXIT_FAIL_CLOSED

    report.emit()
    if report.ok:
        print(
            f"OK mode={args.mode}: steward certificate pinned; all signatures and admission chains verify. "
            "Records are declaration-only."
        )
        return L.EXIT_OK
    print(f"{len(report.errors)} error(s)", file=sys.stderr)
    return L.EXIT_INVALID


class Done(Exception):
    pass


class Invalid(Exception):
    pass


if __name__ == "__main__":
    sys.exit(main())
