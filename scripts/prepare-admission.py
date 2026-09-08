#!/usr/bin/env python3
"""Construct an admission candidate branch reproducibly and stop before signing (plan §7.1).

Subcommands:
  query-intake   Query GitHub (via gh) for a reviewed intake PR and write the review record JSON that
                 `build` consumes. Nothing is inferred: PR, head SHA, author, check run, and the
                 triggering workflow run are all read from the live API.
  build          Create admission/<action-id> from the exact current main commit, apply only the reviewed
                 intake diff (declaration actions) or no diff at all (admission-only actions), re-run the
                 intake validators locally against the reviewed head, emit complete unsigned admission
                 event JSON files, and print every path and SHA-256 the offline signer must verify.

`build` never signs, never commits, and never reads a secret key. Every event field that is not derived
from the reviewed tree (reason, request, authority, evidence) must be supplied explicitly.

Exit codes: 0 candidate prepared, 1 rejected, 2 fail-closed (inputs unavailable).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledgerlib as L  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent
DECLARATION_ACTIONS = set(L.DECLARATION_ACTIONS)
ADMISSION_ONLY_ACTIONS = {
    "mark-disputed",
    "withdraw-admission",
    "reinstate-admission",
    "resolve-dispute",
    "slug-release",
}
DEFAULT_CHECK_NAME = "ledger-validation"


class Rejected(Exception):
    pass


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def dump_event(event: dict[str, Any]) -> bytes:
    return (json.dumps(event, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_evidence(items: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items:
        uri, _, sha = item.partition("=")
        if not uri:
            raise Rejected(f"evidence reference {item!r} has no URI")
        if sha and not (len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
            raise Rejected(f"evidence reference {item!r}: sha256 must be 64 lowercase hex characters")
        out.append({"uri": uri, "sha256": sha or None})
    return out


# --------------------------------------------------------------------------- query-intake (gh-backed)


def gh_json(*args: str) -> Any:
    result = subprocess.run(["gh", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise L.FailClosed(f"gh {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def query_intake(args: argparse.Namespace) -> int:
    repo = args.repo
    pr = gh_json(
        "api",
        f"repos/{repo}/pulls/{args.pr}",
        "-H",
        "Accept: application/vnd.github+json",
    )
    head_sha = str(pr["head"]["sha"])
    if args.expected_head and args.expected_head != head_sha:
        raise Rejected(f"PR head {head_sha} does not equal expected head {args.expected_head}")
    check_runs = gh_json("api", f"repos/{repo}/commits/{head_sha}/check-runs?per_page=100").get("check_runs", [])
    matching = [c for c in check_runs if c.get("name") == args.check_name]
    if not matching:
        raise Rejected(f"no check run named {args.check_name!r} exists for head {head_sha}")
    check = sorted(matching, key=lambda c: str(c.get("completed_at") or ""))[-1]
    run_id = None
    details = str(check.get("details_url") or check.get("html_url") or "")
    for part in details.split("/"):
        if part.isdigit():
            run_id = part
            break
    run = gh_json("api", f"repos/{repo}/actions/runs/{run_id}") if run_id else {}
    files = gh_json("api", f"repos/{repo}/pulls/{args.pr}/files?per_page=100")
    hashes: dict[str, str] = {}
    for f in files:
        path = str(f.get("filename") or "")
        if f.get("status") == "removed":
            continue
        blob = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{repo}/contents/{path}?ref={head_sha}",
                "-H",
                "Accept: application/vnd.github.raw+json",
            ],
            capture_output=True,
        )
        if blob.returncode != 0:
            raise L.FailClosed(f"could not fetch {path}@{head_sha[:12]} from GitHub")
        hashes[path] = L.sha256_bytes(blob.stdout)
    review = {
        "repository": repo,
        "queried_at": now_iso(),
        "pull_request": {
            "number": pr["number"],
            "html_url": pr["html_url"],
            "state": pr["state"],
            "author": pr["user"]["login"],
            "head_repo": (pr["head"].get("repo") or {}).get("full_name"),
            "head_owner": ((pr["head"].get("repo") or {}).get("owner") or {}).get("login"),
            "head_ref": pr["head"]["ref"],
            "head_sha": head_sha,
            "base_repo": pr["base"]["repo"]["full_name"],
            "base_ref": pr["base"]["ref"],
            "base_sha": pr["base"]["sha"],
        },
        "check": {
            "name": check.get("name"),
            "conclusion": check.get("conclusion"),
            "status": check.get("status"),
            "head_sha": check.get("head_sha"),
            "html_url": check.get("html_url"),
            "completed_at": check.get("completed_at"),
        },
        "final_event": {
            "event": run.get("event"),
            "actor": (run.get("triggering_actor") or run.get("actor") or {}).get("login"),
            "run_id": str(run.get("id") or ""),
            "run_attempt": str(run.get("run_attempt") or ""),
            "head_sha": run.get("head_sha"),
        },
        "declaration_hashes": hashes,
    }
    Path(args.out).write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return L.EXIT_OK


# --------------------------------------------------------------------------- build


class Builder:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = Path(args.root).resolve()
        self.git = L.Git(self.root)
        self.intake = ""
        self.primary_pin = ""
        self.subkey_pin = ""
        self.manifest: dict[str, Any] = {
            "action": args.action,
            "declarations": {},
            "historical_records": {},
            "events": {},
            "record_signatures": {},
            "notes": [],
        }

    # -- preconditions ----------------------------------------------------
    def preflight(self) -> str:
        if not self.git.available or not self.git.has_commits():
            raise L.FailClosed("build requires a Git checkout of the ledger with history")
        if not self.git.is_clean():
            raise L.FailClosed("working tree must be clean before preparing a candidate")
        main = self.git.rev_parse(self.args.main_ref)
        if main is None:
            raise L.FailClosed(f"--main-ref {self.args.main_ref} is not a reachable commit; fetch origin first")
        origin_main = self.git.rev_parse("origin/main")
        if origin_main is not None and origin_main != main:
            raise Rejected(
                f"--main-ref {main[:12]} is not the fetched origin/main {origin_main[:12]}; re-fetch and retry"
            )
        if origin_main is None:
            self.manifest["notes"].append("origin/main is not available locally; --main-ref was taken as current main")
        branch = f"admission/{self.args.action_id}"
        if self.git.rev_parse(branch) is not None:
            raise Rejected(f"branch {branch} already exists")
        self.primary_pin = L.read_pin(self.root, L.KEY_REF_PATH)
        self.subkey_pin = L.read_pin(self.root, L.SUBKEY_REF_PATH)
        return main

    def create_branch(self, main: str) -> None:
        branch = f"admission/{self.args.action_id}"
        self.git.run("checkout", "-q", "-b", branch, main)
        self.manifest["branch"] = branch
        self.manifest["base_main"] = main

    # -- declaration actions -------------------------------------------------
    def load_review(self) -> dict[str, Any]:
        p = Path(self.args.review_json)
        if not p.exists():
            raise L.FailClosed(f"--review-json {p} does not exist")
        review = json.loads(p.read_text(encoding="utf-8"))
        pr = review.get("pull_request") or {}
        check = review.get("check") or {}
        if pr.get("state") != "open":
            raise Rejected(f"intake PR is {pr.get('state')!r}; only open, reviewed PRs may be admitted")
        if str(pr.get("head_sha")) != self.intake:
            raise Rejected(f"reviewed head {pr.get('head_sha')} does not equal --intake-ref {self.intake}")
        if str(pr.get("base_repo") or "").lower() != str(review.get("repository") or "").lower():
            raise Rejected("intake PR base repository is not the ledger repository")
        if pr.get("base_ref") != "main":
            raise Rejected("intake PR does not target main")
        if check.get("name") != self.args.check_name:
            raise Rejected(f"required check {self.args.check_name!r} was not the queried check {check.get('name')!r}")
        if check.get("conclusion") != "success" or str(check.get("head_sha")) != self.intake:
            raise Rejected(
                f"required check is not green for head {self.intake[:12]} (conclusion {check.get('conclusion')!r})"
            )
        final = review.get("final_event") or {}
        if str(final.get("head_sha") or self.intake) != self.intake:
            raise Rejected("the green check's workflow run was not produced for the reviewed head")
        if final.get("event") not in (None, "pull_request"):
            raise Rejected(f"the green check was produced by a {final.get('event')!r} run, not a pull_request run")
        if not final.get("actor"):
            raise Rejected("review record lacks the actor of the head-producing event; authority cannot be tied to it")
        return review

    def review_context(self, review: dict[str, Any], base: str) -> dict[str, Any]:
        pr = review["pull_request"]
        final = review.get("final_event") or {}
        action = final.get("action")
        if action not in L.AUTHORITY_EVENT_ACTIONS:
            # The workflow subscribes only to the default pull_request activity types (opened, synchronize,
            # reopened), so a pull_request run for this exact head was produced by one of them.
            action = "synchronize"
            self.manifest["notes"].append(
                "final_event.action derived as 'synchronize' from a pull_request-triggered run for the reviewed head"
            )
        return {
            "event_name": "pull_request",
            "event_action": action,
            "actor": final.get("actor"),
            "run_id": final.get("run_id", ""),
            "repository": review["repository"],
            "sha": self.intake,
            "ref": "refs/heads/main",
            "pull_request": {
                "number": pr.get("number"),
                "html_url": pr.get("html_url"),
                "author": pr.get("author"),
                "head_repo": pr.get("head_repo"),
                "head_owner": pr.get("head_owner"),
                "head_ref": pr.get("head_ref"),
                "head_sha": self.intake,
                "base_repo": pr.get("base_repo"),
                "base_ref": "main",
                "base_sha": base,
            },
        }

    def recheck_intake(self, review: dict[str, Any], base: str) -> None:
        """Re-run both validators in intake mode on the reviewed head, in a throwaway worktree."""
        tmp = Path(tempfile.mkdtemp(prefix="ledger-intake-recheck-"))
        worktree = tmp / "tree"
        ctx_path = tmp / "context.json"
        try:
            self.git.run("worktree", "add", "-q", "--detach", str(worktree), self.intake)
            ctx_path.write_text(json.dumps(self.review_context(review, base), indent=2), encoding="utf-8")
            for script in ("validate.py", "verify-signatures.py"):
                cmd = [
                    sys.executable,
                    str(SCRIPTS / script),
                    "--mode",
                    "intake",
                    "--base-ref",
                    base,
                    "--context",
                    str(ctx_path),
                ]
                if script == "validate.py":
                    cmd += ["--all", "--schema", str(self.root / "schema" / "attestation.schema.json")]
                    cmd += ["--event-schema", str(self.root / "schema" / "admission-event.schema.json")]
                cmd += ["--root", str(worktree)]
                if self.args.gpg:
                    cmd += ["--gpg", self.args.gpg]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    raise Rejected(f"local intake re-check with {script} failed:\n{result.stdout}{result.stderr}")
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=self.root, capture_output=True)
            shutil.rmtree(tmp, ignore_errors=True)

    def apply_intake_diff(self, review: dict[str, Any], base: str) -> list[L.Record]:
        changes = self.git.diff_name_status(base, self.intake)
        if not changes:
            raise Rejected("the reviewed intake head introduces no changes relative to its merge base")
        expected = dict(review.get("declaration_hashes") or {})
        seen: dict[str, str] = {}
        for status, path in changes:
            if not ((path.startswith("attestations/") or path.startswith("revocations/")) and path.endswith(".yaml")):
                raise Rejected(
                    f"intake diff touches non-declaration path {path}; steward artifacts are never applied from intake"
                )
            if status == "D":
                self.git.run("rm", "-q", "--", path)
                continue
            self.git.run("checkout", "-q", self.intake, "--", path)
            seen[path] = L.sha256_file(self.root / path)
        if seen != expected:
            raise Rejected(
                "declaration hashes in the applied diff differ from the reviewed intake tree:\n"
                f"  applied : {json.dumps(seen, sort_keys=True)}\n  reviewed: {json.dumps(expected, sort_keys=True)}"
            )
        records: list[L.Record] = []
        for path in sorted(seen):
            rec = L.parse_record(path, (self.root / path).read_bytes())
            if rec is None:
                raise Rejected(f"{path} is not a parseable declaration")
            records.append(rec)
            self.manifest["declarations"][path] = rec.sha256
        return records

    def emit_admit_events(self, review: dict[str, Any], records: list[L.Record]) -> None:
        pr = review["pull_request"]
        check = review["check"]
        for rec in records:
            if rec.action != self.args.action:
                raise Rejected(
                    f"{rec.path} carries attestation.action {rec.action!r} but this candidate is for "
                    f"{self.args.action!r}"
                )
            slug, sha = rec.slug or "", rec.sha256
            chain_dir = self.root / "admissions"
            if any(chain_dir.glob(f"{slug}.{sha}.*")):
                raise Rejected(f"admission artifacts for {slug}.{sha[:12]} already exist on main")
            event = self.base_event(rec, seq=1, action="admit", status="admitted", declaration_action=rec.action)
            event["request"]["sourceType"] = "github-pr"
            event["request"]["sourceRef"] = pr.get("html_url")
            event["review"] = {
                "intakePr": pr.get("html_url"),
                "headSha": self.intake,
                "checkRun": check.get("html_url"),
                "declarationHashes": dict(review.get("declaration_hashes") or {}),
            }
            self.write_event(f"admissions/{slug}.{sha}.0001.json", event)
            self.manifest["record_signatures"][f"admissions/{slug}.{sha}.record.asc"] = rec.path
            if rec.action == "correct-declaration":
                self.emit_correction(rec, f"admissions/{slug}.{sha}.0001.json")

    def emit_correction(self, new: L.Record, admit_event_path: str) -> None:
        pred = new.predecessor or {}
        old_path, old_sha = str(pred.get("path") or ""), str(pred.get("sha256") or "")
        slug = new.slug or ""
        chains = L.load_chains(self.root)
        chain = chains.get((slug, old_sha))
        if chain is None:
            raise Rejected(f"correct-declaration predecessor {old_path}@{old_sha[:12]} has no admission chain on main")
        if chain.status not in L.ADMISSION_EDGES["correct-admission"][0]:
            raise Rejected(f"predecessor chain is {chain.status!r}; correct-admission requires admitted or disputed")
        blob = self.git.find_blob(old_path, old_sha, self.manifest["base_main"])
        old = L.parse_record(old_path, blob) if blob is not None else None
        if old is None:
            raise Rejected(f"predecessor bytes {old_path}@{old_sha[:12]} are not in main history")
        last = chain.latest
        assert last is not None
        event = self.base_event(old, seq=last.sequence + 1, action="correct-admission", status="corrected")
        event["previousEvent"] = {"path": last.path, "sha256": last.sha256}
        admit_bytes = (self.root / admit_event_path).read_bytes()
        event["correctionRef"] = {
            "declarationId": new.declaration_id,
            "version": new.version,
            "path": new.path,
            "sha256": new.sha256,
            "admissionEvent": {"path": admit_event_path, "sha256": L.sha256_bytes(admit_bytes)},
        }
        self.write_event(f"admissions/{slug}.{old_sha}.{last.sequence + 1:04d}.json", event)

    # -- admission-only actions -----------------------------------------------
    def emit_admission_only(self) -> None:
        action = self.args.action
        record_path = self.args.record
        if not record_path:
            raise L.FailClosed("admission-only actions require --record <declaration path>")
        rec: L.Record | None = None
        if (self.root / record_path).exists():
            rec = L.parse_record(record_path, (self.root / record_path).read_bytes())
        if rec is None or (self.args.record_sha and rec.sha256 != self.args.record_sha):
            if not self.args.record_sha:
                raise L.FailClosed(f"{record_path} is not in the tree; pass --record-sha for a historical record")
            blob = self.git.find_blob(record_path, self.args.record_sha, self.manifest["base_main"])
            rec = L.parse_record(record_path, blob) if blob is not None else None
            if rec is None:
                raise Rejected(f"{record_path}@{self.args.record_sha[:12]} is not in main history")
        slug, sha = rec.slug or "", rec.sha256
        chain = L.load_chains(self.root).get((slug, sha))
        if chain is None or chain.latest is None:
            raise Rejected(
                f"{record_path}@{sha[:12]} has no admission chain; only admitted records take admission-only actions"
            )
        allowed_from, allowed_to = L.ADMISSION_EDGES[action]
        if chain.status not in allowed_from:
            raise Rejected(f"admission edge {chain.status} --{action}--> is not allowed")
        if action == "resolve-dispute":
            status = self.args.status
            if status not in allowed_to:
                raise L.FailClosed("resolve-dispute requires --status admitted|withdrawn")
        elif action == "slug-release":
            status = chain.status or ""
        else:
            status = next(iter(allowed_to))
        last = chain.latest
        event = self.base_event(rec, seq=last.sequence + 1, action=action, status=status)
        event["previousEvent"] = {"path": last.path, "sha256": last.sha256}
        if action == "slug-release":
            event["slugReleased"] = True
            if rec.is_active_path and (self.root / rec.path).exists():
                raise Rejected("slug-release applies only to a lineage whose active record has been withdrawn")
        self.write_event(f"admissions/{slug}.{sha}.{last.sequence + 1:04d}.json", event)
        in_tree = (self.root / rec.path).exists() and L.sha256_file(self.root / rec.path) == sha
        self.manifest["declarations" if in_tree else "historical_records"][rec.path] = sha

    # -- event assembly -------------------------------------------------------------
    def base_event(
        self, rec: L.Record, *, seq: int, action: str, status: str, declaration_action: str | None = None
    ) -> dict[str, Any]:
        a = self.args
        if not a.reason or not a.reason_code:
            raise L.FailClosed("--reason and --reason-code are required; the helper never invents them")
        if not a.request_source_type or not a.request_ref or not a.requested_by:
            raise L.FailClosed("--request-source-type, --request-ref, and --requested-by are required")
        if not a.authority_basis or not a.authority_principal:
            raise L.FailClosed("--authority-basis and --authority-principal are required")
        evidence_ref = parse_evidence([a.authority_evidence])[0] if a.authority_evidence else None
        return {
            "schemaVersion": 1,
            "sequence": seq,
            "action": action,
            "declarationAction": declaration_action,
            "admissionStatus": status,
            "reasonCode": a.reason_code,
            "reason": a.reason,
            "occurredAt": a.occurred_at or now_iso(),
            "record": {
                "declarationId": rec.declaration_id,
                "version": rec.version,
                "path": rec.path,
                "sha256": rec.sha256,
            },
            "actor": {
                "type": "steward",
                "keyRef": f"openpgp:{self.primary_pin}",
                "signingSubkeyRef": f"openpgp:{self.subkey_pin}",
            },
            "request": {
                "sourceType": a.request_source_type,
                "sourceRef": a.request_ref,
                "requestedBy": a.requested_by,
                "evidence": parse_evidence(a.request_evidence or []),
            },
            "authority": {"basis": a.authority_basis, "principal": a.authority_principal, "evidenceRef": evidence_ref},
            "review": None,
            "previousEvent": None,
            "correctionRef": None,
            "slugReleased": False,
        }

    def write_event(self, rel: str, event: dict[str, Any]) -> None:
        p = self.root / rel
        if p.exists():
            raise Rejected(f"{rel} already exists; admissions/ is append-only")
        raw = dump_event(event)
        p.write_bytes(raw)
        self.manifest["events"][rel] = L.sha256_bytes(raw)

    # -- output -----------------------------------------------------------------------
    def print_manifest(self) -> None:
        m = self.manifest
        print(f"candidate branch {m['branch']} created from main {m['base_main']}")
        print("declaration bytes (verify before signing):")
        for path, sha in sorted(m["declarations"].items()):
            print(f"  {sha}  {path}")
        for path, sha in sorted(m["historical_records"].items()):
            print(f"  {sha}  {path}  [historical bytes from main history; not in the tree]")
        print("unsigned admission events written (verify, then sign):")
        for path, sha in sorted(m["events"].items()):
            print(f"  {sha}  {path}")
        for note in m["notes"]:
            print(f"note: {note}")
        print()
        print("offline signing steps (pinned signing subkey):")
        for sig, record in sorted(m["record_signatures"].items()):
            print(f"  gpg --local-user {self.subkey_pin}! --detach-sign --armor -o {sig} {record}")
        for path in sorted(m["events"]):
            print(f"  gpg --local-user {self.subkey_pin}! --detach-sign --armor -o {path}.asc {path}")
        print(
            f"  git add -A && git commit -S --gpg-sign={self.subkey_pin}! "
            f'-m "{self.args.action}: {self.args.action_id}"'
        )
        print("No declaration byte may change after this point; the admission-mode validators will reject any drift.")
        if self.args.manifest:
            out = Path(self.args.manifest)
            if out.resolve().is_relative_to(self.root):
                raise L.FailClosed("--manifest must be written outside the repository")
            out.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(args: argparse.Namespace) -> int:
    b = Builder(args)
    main = b.preflight()
    if args.action in DECLARATION_ACTIONS:
        if not args.intake_ref or not args.review_json:
            raise L.FailClosed("declaration actions require --intake-ref <sha> and --review-json <file>")
        intake = b.git.rev_parse(args.intake_ref)
        if intake is None:
            raise L.FailClosed(
                f"--intake-ref {args.intake_ref} is not a reachable commit; fetch refs/pull/<n>/head first"
            )
        b.intake = intake
        review = b.load_review()
        base = b.git.merge_base(main, intake)
        if base is None:
            raise Rejected("intake head shares no history with main")
        b.recheck_intake(review, base)
        b.create_branch(main)
        try:
            records = b.apply_intake_diff(review, base)
            b.emit_admit_events(review, records)
        except Exception:
            rollback(b, main)
            raise
    elif args.action in ADMISSION_ONLY_ACTIONS:
        if args.intake_ref or args.review_json:
            raise Rejected(
                "admission-only actions start with no declaration diff; do not pass --intake-ref/--review-json"
            )
        b.create_branch(main)
        try:
            b.emit_admission_only()
        except Exception:
            rollback(b, main)
            raise
    else:
        raise L.FailClosed(f"unknown action {args.action!r}")
    b.print_manifest()
    return L.EXIT_OK


def rollback(b: Builder, main: str) -> None:
    branch = b.manifest.get("branch")
    subprocess.run(["git", "reset", "-q", "--hard", main], cwd=b.root, capture_output=True)
    subprocess.run(
        ["git", "clean", "-qfd", "admissions", "attestations", "revocations"], cwd=b.root, capture_output=True
    )
    subprocess.run(["git", "checkout", "-q", "--detach", main], cwd=b.root, capture_output=True)
    if branch:
        subprocess.run(["git", "branch", "-q", "-D", branch], cwd=b.root, capture_output=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    q = sub.add_parser("query-intake", help="query GitHub for a reviewed intake PR and write the review record")
    q.add_argument("--repo", required=True, help="owner/name, e.g. FIDES-ANIMA/protocol-attestation-ledger")
    q.add_argument("--pr", required=True, type=int)
    q.add_argument("--expected-head", help="reject if the PR head moved away from this SHA")
    q.add_argument("--check-name", default=DEFAULT_CHECK_NAME)
    q.add_argument("--out", required=True)

    b = sub.add_parser("build", help="create admission/<action-id> and emit unsigned admission events")
    b.add_argument("--root", default=".")
    b.add_argument("--action", required=True, choices=sorted(DECLARATION_ACTIONS | ADMISSION_ONLY_ACTIONS))
    b.add_argument("--action-id", required=True, help="branch suffix: admission/<action-id>")
    b.add_argument("--main-ref", required=True, help="exact current main commit (fetched origin/main)")
    b.add_argument("--intake-ref", help="reviewed intake head SHA (declaration actions)")
    b.add_argument("--review-json", help="review record written by query-intake (declaration actions)")
    b.add_argument("--check-name", default=DEFAULT_CHECK_NAME)
    b.add_argument("--record", help="declaration path for admission-only actions")
    b.add_argument("--record-sha", help="declaration SHA-256 when the record is no longer in the tree")
    b.add_argument("--status", choices=("admitted", "withdrawn"), help="resolve-dispute outcome")
    b.add_argument("--reason-code", help="short machine code, e.g. intake-reviewed")
    b.add_argument("--reason", help="human-readable reason recorded in the event")
    b.add_argument("--request-source-type", choices=("github-pr", "github-issue", "out-of-band", "steward-initiated"))
    b.add_argument("--request-ref", help="URL or recorded reference of the request")
    b.add_argument("--requested-by", help="who asked, e.g. github:alice or fpp:ed25519:...")
    b.add_argument("--request-evidence", action="append", help="uri[=sha256], repeatable")
    b.add_argument(
        "--authority-basis",
        choices=(
            "agent-signature",
            "github-pr-author-match",
            "out-of-band-request",
            "steward-discretion",
            "dispute-review",
        ),
    )
    b.add_argument("--authority-principal", help="the principal whose authority was verified")
    b.add_argument("--authority-evidence", help="uri[=sha256] for the authority decision")
    b.add_argument("--occurred-at", help="ISO 8601 UTC timestamp (default: now)")
    b.add_argument("--manifest", help="write the manifest JSON here (outside the repository)")
    b.add_argument("--gpg", help="gpg binary for the local intake re-check")
    args = ap.parse_args(argv)

    try:
        if args.command == "query-intake":
            return query_intake(args)
        return build(args)
    except Rejected as exc:
        print(f"REJECTED {exc}", file=sys.stderr)
        return L.EXIT_INVALID
    except L.FailClosed as exc:
        print(f"FAIL (closed) {exc}", file=sys.stderr)
        return L.EXIT_FAIL_CLOSED


if __name__ == "__main__":
    sys.exit(main())
