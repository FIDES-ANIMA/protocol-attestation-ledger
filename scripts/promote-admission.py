#!/usr/bin/env python3
"""Promote a verified admission PR head to main by fast-forward only (plan §7.1, promote steps 1-7).

The helper re-queries live state (or reads a freshly queried record with --pr-json for fixture proof),
rejects stale caller-supplied SHAs, verifies the head locally with both validators in admission mode,
requires current main to be an ancestor of the head, pushes exactly that SHA to main without force, and
confirms the remote main equals it. It never signs, never creates commits, and never merges.

Exit codes: 0 promoted (or --dry-run verified), 1 rejected, 2 fail-closed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledgerlib as L  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent
DEFAULT_CHECK_NAME = "ledger-validation"
# The ledger workflow is identified by its committed path, which GitHub reports on every workflow run as
# `path`. Names are free text (any workflow may call itself ledger-validation); numeric workflow ids are
# stable per repository but differ between the ledger and its forks, so the path is the portable identity.
DEFAULT_WORKFLOW_PATH = ".github/workflows/validate.yml"


class Rejected(Exception):
    pass


def describe_run(run: dict[str, Any]) -> str:
    return (
        f"run {run.get('id')} (workflow {run.get('path')!r}, branch {run.get('head_branch')!r}, "
        f"event {run.get('event')!r}, attempt {run.get('run_attempt')!r}, sha {str(run.get('head_sha') or '')[:12]})"
    )


def is_expected_main_run(run: dict[str, Any], head: str, workflow_path: str) -> bool:
    """True only for the ledger workflow's push-triggered run on main for exactly this SHA."""
    return (
        run.get("path") == workflow_path
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("head_sha") == head
    )


def run_attempt_of(run: dict[str, Any]) -> int | None:
    attempt = run.get("run_attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        return None
    return attempt


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def gh_json(*args: str) -> Any:
    result = subprocess.run(["gh", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise L.FailClosed(f"gh {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def query_pr(repo: str, number: int, check_name: str) -> dict[str, Any]:
    pr = gh_json("api", f"repos/{repo}/pulls/{number}")
    head_sha = str(pr["head"]["sha"])
    check_runs = gh_json("api", f"repos/{repo}/commits/{head_sha}/check-runs?per_page=100").get("check_runs", [])
    matching = sorted(
        (c for c in check_runs if c.get("name") == check_name), key=lambda c: str(c.get("completed_at") or "")
    )
    check = matching[-1] if matching else {}
    run: dict[str, Any] = {}
    run_id = next((p for p in str(check.get("details_url") or "").split("/") if p.isdigit()), None)
    if run_id:
        run = gh_json("api", f"repos/{repo}/actions/runs/{run_id}")
    return {
        "repository": repo,
        "queried_at": now_iso(),
        "source": "gh",
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
        },
        "final_event": {
            "event": run.get("event"),
            "actor": (run.get("triggering_actor") or run.get("actor") or {}).get("login"),
            "run_id": str(run.get("id") or ""),
            "run_attempt": str(run.get("run_attempt") or ""),
            "head_sha": run.get("head_sha"),
        },
    }


class Promoter:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = Path(args.root).resolve()
        self.git = L.Git(self.root)
        self.log: dict[str, Any] = {"started_at": now_iso(), "steps": []}

    def step(self, msg: str) -> None:
        self.log["steps"].append(msg)
        print(f"step: {msg}")

    # -- 1. live state ------------------------------------------------------------
    def load_state(self) -> dict[str, Any]:
        if self.args.pr_json:
            state = json.loads(Path(self.args.pr_json).read_text(encoding="utf-8"))
            state.setdefault("source", "file")
            self.step(
                f"PR state read from {self.args.pr_json} (must have been queried moments ago; nothing is inferred)"
            )
        else:
            if self.args.pr is None:
                raise L.FailClosed("--pr <number> (live) or --pr-json <file> is required")
            state = query_pr(self.args.repo, self.args.pr, self.args.check_name)
            self.step("PR, check run, and workflow run re-queried from GitHub")
        if str(state.get("repository") or "").lower() != self.args.repo.lower():
            raise Rejected(f"state describes {state.get('repository')!r}, not {self.args.repo!r}")
        return state

    # -- 2/3. branch, actor, head, check --------------------------------------------
    def check_state(self, state: dict[str, Any], allow: set[str]) -> str:
        pr = state["pull_request"]
        check = state.get("check") or {}
        final = state.get("final_event") or {}
        head = str(pr.get("head_sha") or "")
        if head != self.args.expected_head:
            raise Rejected(f"PR head {head} does not equal the expected head {self.args.expected_head}; head moved")
        if pr.get("state") != "open":
            raise Rejected(f"admission PR is {pr.get('state')!r}")
        if str(pr.get("base_repo") or "").lower() != self.args.repo.lower():
            raise Rejected("PR base repository is not the ledger")
        if str(pr.get("head_repo") or "").lower() != self.args.repo.lower():
            raise Rejected(f"admission branch lives in {pr.get('head_repo')!r}; it must be in the base repository")
        if pr.get("base_ref") != "main":
            raise Rejected("admission PR must target main")
        if not str(pr.get("head_ref") or "").startswith("admission/"):
            raise Rejected(f"admission branch must be named admission/*, got {pr.get('head_ref')!r}")
        for label, login in (
            ("PR author", pr.get("author")),
            ("final head-producing event actor", final.get("actor")),
        ):
            if not login or str(login).lower() not in allow:
                raise Rejected(f"{label} {login!r} is not in {L.ALLOWLIST_PATH}")
        if check.get("name") != self.args.check_name:
            raise Rejected(f"required check {self.args.check_name!r} not found (got {check.get('name')!r})")
        if check.get("conclusion") != "success" or str(check.get("head_sha") or "") != head:
            raise Rejected(f"required check is not green for {head[:12]} (conclusion {check.get('conclusion')!r})")
        if final.get("head_sha") not in (None, head):
            raise Rejected("the green check's workflow run was not produced for this head")
        self.step(
            f"admission branch {pr['head_ref']} in base repo, steward actors, exact head {head[:12]}, green check"
        )
        return head

    # -- 4/5. local verification ------------------------------------------------------
    def fetch(self, state: dict[str, Any], head: str) -> None:
        head_ref = str(state["pull_request"]["head_ref"])
        self.git.run("fetch", "-q", "origin", "refs/heads/main", f"refs/heads/{head_ref}")
        remote_head = self.git.run("ls-remote", "origin", f"refs/heads/{head_ref}").split()
        if not remote_head or remote_head[0] != head:
            raise Rejected(
                f"remote {head_ref} is at {remote_head[0][:12] if remote_head else 'nothing'}, not {head[:12]}"
            )
        if self.git.rev_parse(head) is None:
            raise L.FailClosed(f"head {head} was not fetched")

    def check_ancestry(self, head: str) -> str:
        main = self.git.rev_parse("origin/main")
        if main is None:
            raise L.FailClosed("origin/main could not be resolved after fetch")
        parents = self.git.run("rev-list", "--parents", "-n", "1", head).split()
        if len(parents) != 2:
            raise Rejected("admission head must be a single-parent commit; merge commits are never promoted")
        if not self.git.is_ancestor(main, head):
            raise Rejected(
                f"current main {main[:12]} is not an ancestor of {head[:12]}; rebuild the candidate from main"
            )
        if main == head:
            raise Rejected("head already equals main; nothing to promote")
        self.log["old_main"] = main
        self.step(f"fetched; main {main[:12]} is an ancestor of single-parent head {head[:12]}")
        return main

    def context_for(self, state: dict[str, Any], head: str, main: str) -> dict[str, Any]:
        pr = state["pull_request"]
        final = state.get("final_event") or {}
        action = final.get("action") if final.get("action") in L.AUTHORITY_EVENT_ACTIONS else "synchronize"
        return {
            "event_name": "pull_request",
            "event_action": action,
            "actor": final.get("actor"),
            "run_id": final.get("run_id", ""),
            "repository": state["repository"],
            "sha": head,
            "ref": "refs/heads/main",
            "pull_request": {
                "number": pr.get("number"),
                "html_url": pr.get("html_url"),
                "author": pr.get("author"),
                "head_repo": pr.get("head_repo"),
                "head_owner": pr.get("head_owner"),
                "head_ref": pr.get("head_ref"),
                "head_sha": head,
                "base_repo": pr.get("base_repo"),
                "base_ref": "main",
                "base_sha": main,
            },
        }

    def verify_locally(self, state: dict[str, Any], head: str, main: str) -> list[str]:
        tmp = Path(tempfile.mkdtemp(prefix="ledger-promote-"))
        worktree = tmp / "tree"
        ctx_path = tmp / "context.json"
        try:
            self.git.run("worktree", "add", "-q", "--detach", str(worktree), head)
            ctx_path.write_text(json.dumps(self.context_for(state, head, main), indent=2), encoding="utf-8")
            failures: list[str] = []
            for script in ("validate.py", "verify-signatures.py"):
                cmd = [sys.executable, str(SCRIPTS / script), "--mode", "admission", "--base-ref", main]
                cmd += ["--context", str(ctx_path), "--root", str(worktree)]
                if script == "validate.py":
                    cmd += ["--all"]
                if self.args.gpg:
                    cmd += ["--gpg", self.args.gpg]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    failures.append(f"{script} --mode admission rejected {head[:12]}:\n{result.stdout}{result.stderr}")
            if failures:
                raise Rejected("\n".join(failures))
            events = [
                p
                for s, p in self.git.diff_name_status(main, head)
                if p.startswith("admissions/") and p.endswith(".json")
            ]
            self.check_embedded(state, worktree, events)
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=self.root, capture_output=True)
            shutil.rmtree(tmp, ignore_errors=True)
        self.step("validate.py and verify-signatures.py passed in admission mode on the exact head")
        return events

    def check_embedded(self, state: dict[str, Any], worktree: Path, events: list[str]) -> None:
        """Compare what each signed event embeds against the re-queried intake review, when one is supplied."""
        review_path = self.args.intake_review_json
        review = json.loads(Path(review_path).read_text(encoding="utf-8")) if review_path else None
        for rel in events:
            doc = json.loads((worktree / rel).read_text(encoding="utf-8"))
            if doc.get("action") != "admit":
                continue
            rv = doc.get("review") or {}
            for path, sha in (rv.get("declarationHashes") or {}).items():
                f = worktree / path
                if not f.exists() or L.sha256_file(f) != sha:
                    raise Rejected(f"{rel}: review.declarationHashes[{path}] does not match the candidate tree")
            if review is None:
                self.log.setdefault("warnings", []).append(
                    f"{rel}: intake head/check/authority not re-compared (no --intake-review-json); "
                    "validators still bound hashes"
                )
                continue
            ipr = review.get("pull_request") or {}
            ichk = review.get("check") or {}
            if rv.get("headSha") != ipr.get("head_sha"):
                raise Rejected(
                    f"{rel}: review.headSha {rv.get('headSha')} differs from re-queried intake head "
                    f"{ipr.get('head_sha')}"
                )
            if rv.get("intakePr") != ipr.get("html_url"):
                raise Rejected(f"{rel}: review.intakePr does not name the re-queried intake PR")
            if rv.get("checkRun") != ichk.get("html_url") or ichk.get("conclusion") != "success":
                raise Rejected(f"{rel}: review.checkRun is not the re-queried green check run")
            if dict(rv.get("declarationHashes") or {}) != dict(review.get("declaration_hashes") or {}):
                raise Rejected(f"{rel}: review.declarationHashes differ from the re-queried intake tree")
            auth = doc.get("authority") or {}
            if (
                auth.get("basis") == "github-pr-author-match"
                and str(auth.get("principal") or "").lower() != f"github:{str(ipr.get('author') or '').lower()}"
            ):
                raise Rejected(f"{rel}: authority.principal does not match the re-queried intake PR author")

    # -- 6/7. promote -------------------------------------------------------------------------
    def push(self, head: str, main: str) -> None:
        if self.args.dry_run:
            self.step("dry run: fast-forward push skipped")
            return
        self.git.run("push", "origin", f"{head}:refs/heads/main")
        self.git.run("fetch", "-q", "origin", "refs/heads/main")
        remote = self.git.run("ls-remote", "origin", "refs/heads/main").split()
        if not remote or remote[0] != head:
            raise Rejected(f"remote main is {remote[0][:12] if remote else 'unknown'} after push, not {head[:12]}")
        self.log["new_main"] = head
        self.step(f"main fast-forwarded {main[:12]} -> {head[:12]} and confirmed on the remote")

    def observe_main(self, head: str) -> None:
        if self.args.dry_run:
            return
        if self.args.pr_json and not self.args.observe_main:
            self.log.setdefault("warnings", []).append(
                "main workflow not observed (offline state); confirm the main run is green"
            )
            self.step("main workflow observation skipped (--pr-json without --observe-main)")
            return
        # The admission PR run and the post-promotion main run share the same head SHA, so check-runs on the
        # commit cannot tell them apart (first live promotion, 2026-09-08, recorded the PR run here). Nor is
        # "some push workflow went green" evidence: any other workflow that runs on push to main would satisfy
        # that. Only the ledger workflow itself, identified by its committed path, triggered by `push` on
        # `main` for this exact SHA counts as the main-mode result, and its latest attempt is what GitHub
        # reports, so a re-run that failed after an earlier success is seen as the failure it is.
        workflow_path = str(self.args.workflow_path)
        deadline = time.time() + self.args.observe_timeout
        seen_other: set[str] = set()
        while time.time() < deadline:
            runs = gh_json(
                "api",
                f"repos/{self.args.repo}/actions/runs?branch=main&event=push&head_sha={head}&per_page=50",
            ).get("workflow_runs", [])
            ours = [r for r in runs if is_expected_main_run(r, head, workflow_path)]
            for other in runs:
                if other not in ours and str(other.get("id")) not in seen_other:
                    seen_other.add(str(other.get("id")))
                    self.log.setdefault("ignored_runs", []).append(describe_run(other))
            if len(ours) > 1:
                raise Rejected(
                    f"{len(ours)} push runs of {workflow_path} exist on main for {head[:12]}; the observation is "
                    "ambiguous and main may have moved back and forth, inspect by hand: "
                    + "; ".join(describe_run(r) for r in ours)
                )
            if ours:
                run = ours[0]
                attempt = run_attempt_of(run)
                if attempt is None:
                    raise Rejected(f"main workflow {describe_run(run)} reports no valid run_attempt")
                if run.get("status") == "completed":
                    if run.get("conclusion") != "success":
                        raise Rejected(
                            f"main workflow {describe_run(run)} concluded {run.get('conclusion')!r} on {head[:12]}"
                        )
                    self.log["main_run"] = run.get("html_url")
                    self.log["main_run_id"] = run.get("id")
                    self.log["main_run_attempt"] = attempt
                    self.log["main_workflow_path"] = workflow_path
                    self.log["main_workflow_id"] = run.get("workflow_id")
                    if attempt > 1:
                        self.log.setdefault("warnings", []).append(
                            f"main run {run.get('id')} is green only on attempt {attempt}; the tree at {head[:12]} "
                            "is immutable, so an earlier attempt failed for environmental reasons. Confirm that "
                            "before treating the promotion as clean."
                        )
                    self.step(
                        f"main workflow {workflow_path} (push event on main, attempt {attempt}) is green on the "
                        f"promoted SHA: run {run.get('id')}"
                    )
                    return
            time.sleep(15)
        raise Rejected(
            f"timed out waiting for the {workflow_path} push run on main for {head[:12]}; "
            "do not consider the promotion complete"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="steward clone with an `origin` remote pointing at the ledger")
    ap.add_argument("--repo", required=True, help="owner/name of the ledger repository")
    ap.add_argument("--pr", type=int, help="admission PR number (live query via gh)")
    ap.add_argument("--pr-json", help="freshly queried PR state (fixture proof / offline verification)")
    ap.add_argument("--intake-review-json", help="re-queried intake review record to compare embedded event fields")
    ap.add_argument("--expected-head", required=True, help="the exact admission head SHA the steward verified offline")
    ap.add_argument("--check-name", default=DEFAULT_CHECK_NAME)
    ap.add_argument(
        "--workflow-path",
        default=DEFAULT_WORKFLOW_PATH,
        help="committed path of the ledger workflow whose push run on main is observed after promotion",
    )
    ap.add_argument("--dry-run", action="store_true", help="verify everything but do not push")
    ap.add_argument(
        "--observe-main", action="store_true", help="poll the main workflow after pushing (default when live)"
    )
    ap.add_argument("--observe-timeout", type=int, default=900)
    ap.add_argument("--gpg", help="gpg binary for the local verification")
    ap.add_argument("--log", help="write the operator log JSON here (outside the repository)")
    args = ap.parse_args(argv)
    if not args.pr_json:
        args.observe_main = True

    p = Promoter(args)
    try:
        if not p.git.available:
            raise L.FailClosed(f"{p.root} is not a Git checkout")
        state = p.load_state()
        pr = state["pull_request"]
        head = str(pr.get("head_sha") or "")
        if head != args.expected_head:
            raise Rejected(f"PR head {head[:12]} does not equal expected head {args.expected_head[:12]}; head moved")
        if not str(pr.get("head_ref") or "").startswith("admission/"):
            raise Rejected(f"admission branch must be named admission/*, got {pr.get('head_ref')!r}")
        p.fetch(state, head)
        allow_text = p.git.show(head, L.ALLOWLIST_PATH)
        if allow_text is None:
            raise L.FailClosed(f"{L.ALLOWLIST_PATH} is missing from the admission head; refusing")
        allow = {ln.split("#", 1)[0].strip().lower() for ln in allow_text.decode("utf-8").splitlines()}
        allow.discard("")
        p.check_state(state, allow)
        main_sha = p.check_ancestry(head)
        events = p.verify_locally(state, head, main_sha)
        p.push(head, main_sha)
        p.observe_main(head)
        p.log.update(
            {
                "pr": pr.get("html_url"),
                "head": head,
                "actor": (state.get("final_event") or {}).get("actor"),
                "check_run": (state.get("check") or {}).get("html_url"),
                "admission_events": events,
                "finished_at": now_iso(),
            }
        )
    except Rejected as exc:
        print(f"REJECTED {exc}", file=sys.stderr)
        return L.EXIT_INVALID
    except L.FailClosed as exc:
        print(f"FAIL (closed) {exc}", file=sys.stderr)
        return L.EXIT_FAIL_CLOSED
    except subprocess.CalledProcessError as exc:
        print(
            f"REJECTED git {' '.join(map(str, exc.cmd[1:3]))} failed: {exc.stderr.decode('utf-8', 'replace').strip()}",
            file=sys.stderr,
        )
        return L.EXIT_INVALID
    finally:
        if args.log:
            out = Path(args.log)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(p.log, indent=2) + "\n", encoding="utf-8")
    for w in p.log.get("warnings", []):
        print(f"warning: {w}")
    print("OK promotion " + ("verified (dry run)" if args.dry_run else f"complete: main is {p.log.get('new_main')}"))
    return L.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
