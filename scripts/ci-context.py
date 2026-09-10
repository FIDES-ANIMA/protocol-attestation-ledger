#!/usr/bin/env python3
"""Derive the validation mode and trusted context file from GitHub Actions event data.

Reads only runner-provided inputs (GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_REPOSITORY, GITHUB_ACTOR,
GITHUB_TRIGGERING_ACTOR, GITHUB_SHA, GITHUB_REF, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT) and the committed steward
actor allowlist. Never reads PR titles, bodies, labels, or other contributor-controlled text.

Mode:
  push to refs/heads/main                                   -> main
  pull_request into main from admission/* in this repo      -> admission (actor must be an allowlisted steward)
  pull_request into main from anywhere else                 -> intake
  anything else                                             -> fail closed (exit 2)

The mode is derived from trust context only. Whether an intake PR is a declaration intake or a maintenance
proposal is decided by validate.py from the committed diff (GOVERNANCE.md §5a), never from PR text here.

Writes the context JSON consumed by validate.py/verify-signatures.py --context, and prints
mode=, base_sha=, head_sha= lines (also appended to $GITHUB_OUTPUT when set).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledgerlib as L  # noqa: E402


def fail(msg: str) -> int:
    print(f"FAIL (closed) {msg}", file=sys.stderr)
    return L.EXIT_FAIL_CLOSED


def derive(env: dict[str, str], event: dict[str, Any], root: Path) -> tuple[str, dict[str, Any]]:
    event_name = env.get("GITHUB_EVENT_NAME", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    actor = env.get("GITHUB_TRIGGERING_ACTOR") or env.get("GITHUB_ACTOR", "")
    if not repository or not actor:
        raise L.FailClosed("GITHUB_REPOSITORY and GITHUB_ACTOR are required")
    ctx: dict[str, Any] = {
        "event_name": event_name,
        "event_action": str(event.get("action") or ""),
        "actor": actor,
        "run_id": env.get("GITHUB_RUN_ID", ""),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "repository": repository,
        "sha": env.get("GITHUB_SHA", ""),
        "ref": env.get("GITHUB_REF", ""),
    }
    if event_name == "push":
        if ctx["ref"] != "refs/heads/main":
            raise L.FailClosed(f"push validation only runs for refs/heads/main, got {ctx['ref']!r}")
        after = str(event.get("after") or ctx["sha"])
        if after != ctx["sha"]:
            raise L.FailClosed("push event 'after' does not equal GITHUB_SHA")
        return "main", ctx
    if event_name != "pull_request":
        raise L.FailClosed(f"unsupported event {event_name!r}; only push to main and pull_request are validated")
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        raise L.FailClosed("pull_request payload is missing")
    base = pr.get("base") or {}
    head = pr.get("head") or {}
    base_repo = str(((base.get("repo") or {}).get("full_name")) or "")
    head_repo_obj = head.get("repo")
    if not isinstance(head_repo_obj, dict):
        raise L.FailClosed("pull request head repository is unavailable (deleted fork?)")
    head_repo = str(head_repo_obj.get("full_name") or "")
    head_owner = str(((head_repo_obj.get("owner") or {}).get("login")) or head_repo.split("/")[0])
    if base_repo.lower() != repository.lower():
        raise L.FailClosed(f"pull request base repository {base_repo!r} is not {repository!r}")
    if str(base.get("ref")) != "main":
        raise L.FailClosed(f"pull requests must target main, got {base.get('ref')!r}")
    if pr.get("state") not in (None, "open"):
        raise L.FailClosed(f"pull request is {pr.get('state')!r}, not open")
    ctx["pull_request"] = {
        "number": pr.get("number"),
        "html_url": pr.get("html_url"),
        "author": str(((pr.get("user") or {}).get("login")) or ""),
        "head_repo": head_repo,
        "head_owner": head_owner,
        "head_ref": str(head.get("ref") or ""),
        "head_sha": str(head.get("sha") or ""),
        "base_repo": base_repo,
        "base_ref": str(base.get("ref") or ""),
        "base_sha": str(base.get("sha") or ""),
    }
    if not ctx["pull_request"]["head_sha"] or not ctx["pull_request"]["base_sha"]:
        raise L.FailClosed("pull request head/base SHAs are missing from the event payload")
    in_base_repo = head_repo.lower() == repository.lower()
    if in_base_repo and ctx["pull_request"]["head_ref"].startswith("admission/"):
        allow = L.load_allowlist(root)
        if allow is None:
            raise L.FailClosed(f"{L.ALLOWLIST_PATH} is missing; admission branches cannot be validated")
        if actor.lower() not in allow or ctx["pull_request"]["author"].lower() not in allow:
            raise L.FailClosed(
                f"admission/* branch driven by actor {actor!r} / author {ctx['pull_request']['author']!r} "
                f"who is not in {L.ALLOWLIST_PATH}"
            )
        return "admission", ctx
    return "intake", ctx


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="where to write the context JSON (outside the checkout)")
    ap.add_argument("--root", default=".", help="repository checkout (for the steward actor allowlist)")
    ap.add_argument("--event-path", help="override GITHUB_EVENT_PATH (tests)")
    args = ap.parse_args(argv)
    env = dict(os.environ)
    event_path = args.event_path or env.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).exists():
        return fail("GITHUB_EVENT_PATH is missing; cannot derive a trusted context")
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            raise L.FailClosed("event payload is not a JSON object")
        mode, ctx = derive(env, event, Path(args.root).resolve())
    except (json.JSONDecodeError, L.FailClosed) as exc:
        return fail(str(exc))
    out = Path(args.out)
    if out.resolve().is_relative_to(Path(args.root).resolve()):
        return fail("--out must be outside the repository checkout so it can never be committed")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ctx, indent=2) + "\n", encoding="utf-8")
    head_sha = ctx["pull_request"]["head_sha"] if mode != "main" else ctx["sha"]
    base_sha = ctx["pull_request"]["base_sha"] if mode != "main" else ""
    lines = [f"mode={mode}", f"base_sha={base_sha}", f"head_sha={head_sha}", f"context={out}"]
    for line in lines:
        print(line)
    gh_out = env.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return L.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
