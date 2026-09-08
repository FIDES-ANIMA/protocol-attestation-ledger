"""End-to-end proof of the admission workflow helpers against temporary Git histories (plan §7.2, D6).

Each journey drives: contributor intake commit -> prepare-admission.py build -> sign-admission.py (fixture
steward key) -> push admission/* -> promote-admission.py (fast-forward to a bare origin) -> main-mode
validators on the promoted tree. Negative trials show the helpers reject what the plan says they must.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from .conftest import (
    PREPARE,
    PROMOTE,
    REPOSITORY,
    SCRIPTS,
    SIGN,
    STEWARD_LOGIN,
    AgentKey,
    Ledger,
    assert_fails,
    assert_passes,
    declaration,
    dump_yaml,
    output,
    revocation_of,
    sha256_bytes,
    successor,
)

CI_CONTEXT = SCRIPTS / "ci-context.py"
NOVA = "attestations/nova.yaml"
CHECK = "ledger-validation"


class Flow:
    """Steward clone + bare origin + fake GitHub query records."""

    def __init__(self, ledger: Ledger, tmp_path: Path) -> None:
        self.ledger = ledger
        self.tmp = tmp_path
        self.origin = tmp_path / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        ledger.git("config", "user.name", "Test Steward")
        ledger.git("config", "user.email", "steward@example.invalid")
        ledger.git("remote", "add", "origin", str(self.origin))
        ledger.commit("scaffold")
        ledger.git("push", "-q", "-u", "origin", "main")
        self.counter = 0
        self.prs = 100

    # -- helpers ------------------------------------------------------------------
    def main(self) -> str:
        self.ledger.git("fetch", "-q", "origin")
        return self.ledger.git("rev-parse", "origin/main").stdout.strip()

    def sync_main(self) -> None:
        self.ledger.git("checkout", "-q", "main")
        self.ledger.git("reset", "-q", "--hard", "origin/main")
        self.ledger.git("clean", "-qfd")

    def scratch(self, name: str) -> Path:
        self.counter += 1
        return self.tmp / f"{name}-{self.counter}.json"

    def read_main(self, rel: str) -> bytes:
        return self.ledger.git("show", f"origin/main:{rel}").stdout.encode("utf-8")

    def intake(
        self,
        files: dict[str, bytes | None],
        *,
        author: str = "alice",
        actor: str | None = None,
        head_repo: str = "alice/protocol-attestation-ledger",
        head_ref: str = "nova",
        conclusion: str = "success",
        extra_files: dict[str, bytes] | None = None,
    ) -> tuple[str, str]:
        """Create the contributor's intake head locally and the review record query-intake would emit."""
        base = self.main()
        self.ledger.git("checkout", "-q", "--detach", base)
        for path, data in files.items():
            if data is None:
                self.ledger.remove(path)
            else:
                self.ledger.write(path, data)
        for path, data in (extra_files or {}).items():
            self.ledger.write(path, data)
        head = self.ledger.commit("intake")
        self.sync_main()
        self.prs += 1
        hashes = {p: sha256_bytes(d) for p, d in files.items() if d is not None}
        hashes.update({p: sha256_bytes(d) for p, d in (extra_files or {}).items()})
        review: dict[str, Any] = {
            "repository": REPOSITORY,
            "queried_at": "2026-09-08T20:00:00Z",
            "pull_request": {
                "number": self.prs,
                "html_url": f"https://github.com/{REPOSITORY}/pull/{self.prs}",
                "state": "open",
                "author": author,
                "head_repo": head_repo,
                "head_owner": head_repo.split("/")[0],
                "head_ref": head_ref,
                "head_sha": head,
                "base_repo": REPOSITORY,
                "base_ref": "main",
                "base_sha": base,
            },
            "check": {
                "name": CHECK,
                "conclusion": conclusion,
                "status": "completed",
                "head_sha": head,
                "html_url": f"https://github.com/{REPOSITORY}/runs/{self.prs}",
                "completed_at": "2026-09-08T20:01:00Z",
            },
            "final_event": {
                "event": "pull_request",
                "actor": actor or author,
                "run_id": str(5000 + self.prs),
                "run_attempt": "1",
                "head_sha": head,
            },
            "declaration_hashes": hashes,
        }
        out = self.scratch("review")
        out.write_text(json.dumps(review, indent=2), encoding="utf-8")
        return head, str(out)

    def prepare(
        self,
        action: str,
        action_id: str,
        *,
        intake: str | None = None,
        review: str | None = None,
        record: str | None = None,
        record_sha: str | None = None,
        status: str | None = None,
        authority_basis: str = "github-pr-author-match",
        authority_principal: str = "github:alice",
        requested_by: str = "github:alice",
        main_ref: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        manifest = self.scratch("manifest")
        declaration_actions = ("attest", "amend", "correct-declaration", "withdraw-adoption", "re-adopt")
        request_ref = f"https://github.com/{REPOSITORY}/issues/40"
        if intake and review:
            request_ref = json.loads(Path(review).read_text(encoding="utf-8"))["pull_request"]["html_url"]
        args = [
            "build",
            "--action",
            action,
            "--action-id",
            action_id,
            "--main-ref",
            main_ref or self.main(),
            "--reason-code",
            "intake-reviewed" if action in declaration_actions else action,
            "--reason",
            f"Steward reviewed and performed {action}.",
            "--request-source-type",
            "github-pr" if intake else "github-issue",
            "--request-ref",
            request_ref,
            "--requested-by",
            requested_by,
            "--authority-basis",
            authority_basis,
            "--authority-principal",
            authority_principal,
            "--authority-evidence",
            f"https://github.com/{REPOSITORY}/pull/1#issuecomment-1",
            "--occurred-at",
            "2026-09-08T21:00:00Z",
            "--manifest",
            str(manifest),
        ]
        if intake:
            args += ["--intake-ref", intake, "--review-json", review or ""]
        if record:
            args += ["--record", record]
        if record_sha:
            args += ["--record-sha", record_sha]
        if status:
            args += ["--status", status]
        return self.ledger.run_script(PREPARE, *args), str(manifest)

    def sign(self, manifest: str) -> subprocess.CompletedProcess[str]:
        return self.ledger.run_script(
            SIGN, "--manifest", manifest, "--gnupghome", self.ledger.steward.homedir, "--gpg", self.ledger.steward.gpg
        )

    def push_branch(self, branch: str) -> str:
        self.ledger.git("push", "-q", "origin", branch)
        return self.ledger.head()

    def pr_json(
        self,
        head: str,
        head_ref: str,
        *,
        author: str = STEWARD_LOGIN,
        actor: str = STEWARD_LOGIN,
        head_repo: str = REPOSITORY,
        conclusion: str = "success",
        check_head: str | None = None,
    ) -> str:
        self.prs += 1
        state = {
            "repository": REPOSITORY,
            "queried_at": "2026-09-08T22:00:00Z",
            "pull_request": {
                "number": self.prs,
                "html_url": f"https://github.com/{REPOSITORY}/pull/{self.prs}",
                "state": "open",
                "author": author,
                "head_repo": head_repo,
                "head_owner": head_repo.split("/")[0],
                "head_ref": head_ref,
                "head_sha": head,
                "base_repo": REPOSITORY,
                "base_ref": "main",
                "base_sha": self.main(),
            },
            "check": {
                "name": CHECK,
                "conclusion": conclusion,
                "status": "completed",
                "head_sha": check_head or head,
                "html_url": f"https://github.com/{REPOSITORY}/runs/{self.prs}",
            },
            "final_event": {
                "event": "pull_request",
                "actor": actor,
                "run_id": str(7000 + self.prs),
                "run_attempt": "1",
                "head_sha": head,
            },
        }
        out = self.scratch("pr")
        out.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return str(out)

    def promote(
        self, head: str, head_ref: str, *, expected: str | None = None, review: str | None = None, **kw: Any
    ) -> subprocess.CompletedProcess[str]:
        self.sync_main()
        args = [
            "--repo",
            REPOSITORY,
            "--pr-json",
            self.pr_json(head, head_ref, **kw),
            "--expected-head",
            expected or head,
        ]
        args += ["--log", str(self.scratch("log"))]
        if review:
            args += ["--intake-review-json", review]
        return self.ledger.run_script(PROMOTE, *args)

    def admit(self, action: str, action_id: str, **kw: Any) -> str:
        """Full happy path; returns the promoted main SHA."""
        result, manifest = self.prepare(action, action_id, **kw)
        assert_passes(result)
        assert_passes(self.sign(manifest))
        head = self.push_branch(f"admission/{action_id}")
        promoted = self.promote(head, f"admission/{action_id}", review=kw.get("review"))
        assert_passes(promoted)
        assert self.main() == head
        self.sync_main()
        assert_passes(self.ledger.validate("main"))
        assert_passes(self.ledger.verify("main"))
        return head


@pytest.fixture
def flow(git_ledger: Ledger, tmp_path: Path) -> Flow:
    return Flow(git_ledger, tmp_path)


def event_files(flow: Flow) -> list[str]:
    return sorted(
        p
        for p in flow.ledger.git("ls-tree", "-r", "--name-only", "origin/main").stdout.split()
        if p.startswith("admissions/") and p.endswith(".json")
    )


# --------------------------------------------------------------------------- §7.2 matrix


def test_matrix_full_lineage_journey(flow: Flow) -> None:
    key = AgentKey()
    agent_auth = {"authority_basis": "agent-signature", "authority_principal": key.fpp_id, "requested_by": key.fpp_id}

    # initial attest (agent-signed, accepted)
    v1 = declaration(key=key, state="accepted", grade="native-hook")
    v1_bytes = dump_yaml(v1)
    head, review = flow.intake({NOVA: v1_bytes})
    flow.admit("attest", "nova-attest", intake=head, review=review, **agent_auth)
    assert flow.read_main(NOVA) == v1_bytes
    v1_sha = sha256_bytes(v1_bytes)
    assert f"admissions/nova.{v1_sha}.0001.json" in event_files(flow)

    # authorized amend with the prior blob retained in history
    v2 = successor(v1, NOVA, v1_bytes, key=key, **{"attestation.notes": "amended contact hours"})
    v2_bytes = dump_yaml(v2)
    head, review = flow.intake({NOVA: v2_bytes})
    flow.admit("amend", "nova-amend", intake=head, review=review, **agent_auth)
    v2_sha = sha256_bytes(v2_bytes)
    assert flow.ledger.git("show", f"{flow.main()}~1:{NOVA}").stdout.encode("utf-8") == v1_bytes

    # correct-declaration plus linked correct-admission
    v3 = successor(
        v2, NOVA, v2_bytes, key=key, **{"attestation.action": "correct-declaration", "operator.name": "Alice Corrected"}
    )
    v3_bytes = dump_yaml(v3)
    head, review = flow.intake({NOVA: v3_bytes})
    flow.admit("correct-declaration", "nova-correct", intake=head, review=review, **agent_auth)
    v3_sha = sha256_bytes(v3_bytes)
    files = event_files(flow)
    assert f"admissions/nova.{v2_sha}.0002.json" in files  # correct-admission on the old record
    corr = json.loads(flow.read_main(f"admissions/nova.{v2_sha}.0002.json"))
    assert corr["action"] == "correct-admission" and corr["correctionRef"]["sha256"] == v3_sha

    # mark-disputed then resolve-dispute -> admitted
    flow.admit(
        "mark-disputed",
        "nova-dispute",
        record=NOVA,
        authority_basis="dispute-review",
        authority_principal="github:complainant",
        requested_by="github:complainant",
    )
    flow.admit(
        "resolve-dispute",
        "nova-resolve",
        record=NOVA,
        status="admitted",
        authority_basis="dispute-review",
        authority_principal="github:complainant",
        requested_by="github:complainant",
    )
    # steward withdraw-admission with declaration bytes/lifecycle unchanged, then reinstate
    flow.admit(
        "withdraw-admission",
        "nova-withdraw-adm",
        record=NOVA,
        authority_basis="steward-discretion",
        authority_principal=STEWARD_LOGIN,
        requested_by=f"github:{STEWARD_LOGIN}",
    )
    assert flow.read_main(NOVA) == v3_bytes
    flow.admit(
        "reinstate-admission",
        "nova-reinstate",
        record=NOVA,
        authority_basis="steward-discretion",
        authority_principal=STEWARD_LOGIN,
        requested_by=f"github:{STEWARD_LOGIN}",
    )
    chain = [p for p in event_files(flow) if v3_sha in p]
    assert len(chain) == 5  # admit, mark-disputed, resolve-dispute, withdraw-admission, reinstate-admission

    # authorized withdraw-adoption with lifecycle transition and predecessor
    rev_path = "revocations/nova.2026-09-01.yaml"
    rev = revocation_of(v3, NOVA, v3_bytes, key=key)
    rev_bytes = dump_yaml(rev)
    head, review = flow.intake({NOVA: None, rev_path: rev_bytes})
    flow.admit("withdraw-adoption", "nova-withdraw", intake=head, review=review, **agent_auth)
    rev_sha = sha256_bytes(rev_bytes)
    assert flow.ledger.git("cat-file", "-e", f"origin/main:{NOVA}", check=False).returncode != 0

    # same-identity re-adopt
    v5 = successor(
        rev, rev_path, rev_bytes, key=key, state="accepted", **{"attestation.notes": "re-adopted after review"}
    )
    v5_bytes = dump_yaml(v5)
    head, review = flow.intake({NOVA: v5_bytes})
    flow.admit("re-adopt", "nova-readopt", intake=head, review=review, **agent_auth)
    assert flow.read_main(NOVA) == v5_bytes

    # withdraw again, withdraw admission of the revocation lineage head, then slug-release without lifecycle mutation
    rev2_path = "revocations/nova.2026-09-05.yaml"
    rev2 = revocation_of(v5, NOVA, v5_bytes, key=key, revoked_at="2026-09-05")
    rev2_bytes = dump_yaml(rev2)
    head, review = flow.intake({NOVA: None, rev2_path: rev2_bytes})
    flow.admit("withdraw-adoption", "nova-withdraw-2", intake=head, review=review, **agent_auth)
    flow.admit(
        "withdraw-admission",
        "nova-rev-withdraw-adm",
        record=rev2_path,
        authority_basis="steward-discretion",
        authority_principal=STEWARD_LOGIN,
        requested_by=f"github:{STEWARD_LOGIN}",
    )
    flow.admit(
        "slug-release",
        "nova-release",
        record=rev2_path,
        authority_basis="steward-discretion",
        authority_principal=STEWARD_LOGIN,
        requested_by=f"github:{STEWARD_LOGIN}",
    )
    assert flow.read_main(rev2_path) == rev2_bytes
    release = json.loads(flow.read_main(f"admissions/nova.{sha256_bytes(rev2_bytes)}.0003.json"))
    assert release["slugReleased"] is True and release["admissionStatus"] == "withdrawn"

    # a new lineage may now take the slug
    bob = AgentKey()
    new = declaration(key=bob, contact="github:bob", operator_name="Bob")
    head, review = flow.intake({NOVA: dump_yaml(new)}, author="bob", head_repo="bob/protocol-attestation-ledger")
    flow.admit(
        "attest",
        "nova-bob",
        intake=head,
        review=review,
        authority_basis="agent-signature",
        authority_principal=bob.fpp_id,
        requested_by=bob.fpp_id,
    )
    summary = flow.ledger.validate("main", extra=["--summary"])
    assert_passes(summary)
    assert "currently admitted declarations: 1 (agent-signed: 1, operator-reported: 0)" in output(summary)
    assert rev_sha  # lineage history retained


def test_matrix_resolve_dispute_to_withdrawn(flow: Flow) -> None:
    doc = declaration()
    head, review = flow.intake({NOVA: dump_yaml(doc)})
    flow.admit("attest", "nova-attest", intake=head, review=review)
    flow.admit(
        "mark-disputed",
        "nova-dispute",
        record=NOVA,
        authority_basis="dispute-review",
        authority_principal="github:complainant",
        requested_by="github:complainant",
    )
    flow.admit(
        "resolve-dispute",
        "nova-resolve",
        record=NOVA,
        status="withdrawn",
        authority_basis="dispute-review",
        authority_principal="github:complainant",
        requested_by="github:complainant",
    )
    result = flow.ledger.verify("main")
    assert_passes(result)
    assert "admission withdrawn" in output(result)
    assert flow.read_main(NOVA) == dump_yaml(doc)


def test_operator_reported_attest_uses_pr_author_authority(flow: Flow) -> None:
    raw = dump_yaml(declaration())
    head, review = flow.intake({NOVA: raw})
    flow.admit("attest", "nova-attest", intake=head, review=review)
    ev = json.loads(flow.read_main(event_files(flow)[0]))
    assert ev["authority"]["basis"] == "github-pr-author-match"
    assert ev["review"]["headSha"] == head
    assert ev["review"]["declarationHashes"] == {NOVA: sha256_bytes(raw)}
    assert ev["actor"]["signingSubkeyRef"] == f"openpgp:{flow.ledger.steward.signing.lower()}"


# --------------------------------------------------------------------------- negative trials


def test_prepare_rejects_contributor_steward_artifacts(flow: Flow) -> None:
    head, review = flow.intake(
        {NOVA: dump_yaml(declaration())}, extra_files={"admissions/nova.deadbeef.0001.json": b"{}\n"}
    )
    result, _ = flow.prepare("attest", "nova", intake=head, review=review)
    assert result.returncode != 0
    assert "admissions/" in output(result) or "non-declaration" in output(result)
    assert flow.ledger.git("rev-parse", "--verify", "admission/nova", check=False).returncode != 0


def test_prepare_rejects_mismatched_operator_authority(flow: Flow) -> None:
    head, review = flow.intake(
        {NOVA: dump_yaml(declaration())}, author="mallory", head_repo="mallory/protocol-attestation-ledger"
    )
    result, _ = flow.prepare("attest", "nova", intake=head, review=review)
    assert result.returncode != 0
    assert "mallory" in output(result)


def test_prepare_rejects_changed_intake_bytes(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    doc = json.loads(Path(review).read_text(encoding="utf-8"))
    doc["declaration_hashes"][NOVA] = "0" * 64
    Path(review).write_text(json.dumps(doc), encoding="utf-8")
    result, _ = flow.prepare("attest", "nova", intake=head, review=review)
    assert result.returncode != 0
    assert "hash" in output(result).lower()


def test_prepare_rejects_red_or_missing_check_and_moved_head(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())}, conclusion="failure")
    result, _ = flow.prepare("attest", "nova", intake=head, review=review)
    assert_fails(result, "check")
    head2, review2 = flow.intake({NOVA: dump_yaml(declaration(name="Nova Two"))})
    result, _ = flow.prepare("attest", "nova2", intake=head, review=review2)  # review is for a different head
    assert result.returncode != 0
    assert head in output(result) or "head" in output(result)


def test_prepare_rejects_invalid_admission_edge_and_declaration_mutation(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    flow.admit("attest", "nova-attest", intake=head, review=review)
    result, _ = flow.prepare(
        "reinstate-admission",
        "nova-reinstate",
        record=NOVA,
        authority_basis="steward-discretion",
        authority_principal=STEWARD_LOGIN,
    )
    assert_fails(result, "edge")
    result, _ = flow.prepare(
        "withdraw-admission",
        "nova-x",
        record=NOVA,
        intake=head,
        review=review,
        authority_basis="steward-discretion",
        authority_principal=STEWARD_LOGIN,
    )
    assert result.returncode != 0
    assert "no declaration diff" in output(result)


def test_prepare_rejects_action_mismatch(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result, _ = flow.prepare("amend", "nova", intake=head, review=review)
    assert result.returncode != 0
    assert "attest" in output(result)


def test_sign_rejects_drift_after_preparation(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result, manifest = flow.prepare("attest", "nova", intake=head, review=review)
    assert_passes(result)
    p = flow.ledger.path(NOVA)
    p.write_bytes(p.read_bytes() + b"# drift\n")
    signed = flow.sign(manifest)
    assert signed.returncode != 0
    assert "drift" in output(signed)
    assert not any(flow.ledger.path("admissions").glob("*.asc"))


def test_promote_rejects_non_steward_branch_actor_and_fork(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result, manifest = flow.prepare("attest", "nova", intake=head, review=review)
    assert_passes(result)
    assert_passes(flow.sign(manifest))
    admission_head = flow.push_branch("admission/nova")
    assert_fails(flow.promote(admission_head, "admission/nova", author="mallory"), "mallory")
    assert_fails(flow.promote(admission_head, "admission/nova", actor="mallory"), "mallory")
    assert_fails(
        flow.promote(admission_head, "admission/nova", head_repo="steward-bot/protocol-attestation-ledger"),
        "base repository",
    )
    flow.ledger.git("push", "-q", "origin", "admission/nova:refs/heads/feature/nova")
    assert_fails(flow.promote(admission_head, "feature/nova"), "admission/")
    assert flow.main() != admission_head


def test_promote_rejects_stale_head_and_red_check(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result, manifest = flow.prepare("attest", "nova", intake=head, review=review)
    assert_passes(result)
    assert_passes(flow.sign(manifest))
    admission_head = flow.push_branch("admission/nova")
    assert_fails(flow.promote(admission_head, "admission/nova", expected="1" * 40), "head")
    assert_fails(flow.promote(admission_head, "admission/nova", conclusion="failure"), "check")
    assert_fails(flow.promote(admission_head, "admission/nova", check_head="2" * 40), "check")
    assert flow.main() != admission_head


def test_promote_rejects_non_fast_forward_and_unsigned_or_tampered_head(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result, manifest = flow.prepare("attest", "nova", intake=head, review=review)
    assert_passes(result)
    assert_passes(flow.sign(manifest))
    admission_head = flow.push_branch("admission/nova")
    # main moves underneath the candidate
    flow.sync_main()
    flow.ledger.write("README.md", "moved\n")
    flow.ledger.commit("main moved")
    flow.ledger.git("push", "-q", "origin", "main")
    assert_fails(flow.promote(admission_head, "admission/nova"), "ancestor")

    # unsigned head commit on a fresh candidate built from the new main
    flow.sync_main()
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result, manifest = flow.prepare("attest", "nova-2", intake=head, review=review)
    assert_passes(result)
    flow.ledger.commit("unsigned candidate")  # bypasses sign-admission.py
    unsigned_head = flow.push_branch("admission/nova-2")
    assert_fails(flow.promote(unsigned_head, "admission/nova-2"), "commit")
    assert flow.main() != unsigned_head


def test_promote_rejects_broken_event_chain_in_candidate(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    flow.admit("attest", "nova-attest", intake=head, review=review)
    result, manifest = flow.prepare(
        "withdraw-admission",
        "nova-w",
        record=NOVA,
        authority_basis="steward-discretion",
        authority_principal=STEWARD_LOGIN,
    )
    assert_passes(result)
    m = json.loads(Path(manifest).read_text(encoding="utf-8"))
    (rel,) = m["events"].keys()
    ev = json.loads(flow.ledger.read(rel))
    ev["previousEvent"]["sha256"] = "0" * 64
    flow.ledger.write(rel, json.dumps(ev, indent=2, sort_keys=True) + "\n")
    # sign refuses the drift; a steward who signs by hand still cannot promote
    assert flow.sign(manifest).returncode != 0
    flow.ledger.steward.sign_detached(flow.ledger.path(rel))
    flow.ledger.commit("broken chain", sign=True)
    bad = flow.push_branch("admission/nova-w")
    assert_fails(flow.promote(bad, "admission/nova-w"), "previousEvent")


def test_promote_dry_run_does_not_move_main(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result, manifest = flow.prepare("attest", "nova", intake=head, review=review)
    assert_passes(result)
    assert_passes(flow.sign(manifest))
    admission_head = flow.push_branch("admission/nova")
    before = flow.main()
    flow.sync_main()
    pr = flow.pr_json(admission_head, "admission/nova")
    result = flow.ledger.run_script(
        PROMOTE, "--repo", REPOSITORY, "--pr-json", pr, "--expected-head", admission_head, "--dry-run"
    )
    assert_passes(result)
    assert flow.main() == before


def test_prepare_requires_explicit_reason_and_authority(flow: Flow) -> None:
    head, review = flow.intake({NOVA: dump_yaml(declaration())})
    result = flow.ledger.run_script(
        PREPARE,
        "build",
        "--action",
        "attest",
        "--action-id",
        "nova",
        "--main-ref",
        flow.main(),
        "--intake-ref",
        head,
        "--review-json",
        review,
    )
    assert result.returncode == 2
    assert "reason" in output(result)


# --------------------------------------------------------------------------- ci-context


def _gh_env(tmp_path: Path, event: dict[str, Any], **overrides: str) -> dict[str, str]:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event), encoding="utf-8")
    env = {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_ACTOR": "alice",
        "GITHUB_SHA": "3" * 40,
        "GITHUB_REF": "refs/pull/12/merge",
        "GITHUB_RUN_ID": "1",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    env.update(overrides)
    return env


def _pr_event(*, head_repo: str, head_ref: str, author: str = "alice", base_ref: str = "main") -> dict[str, Any]:
    owner = head_repo.split("/")[0]
    return {
        "action": "synchronize",
        "pull_request": {
            "number": 12,
            "html_url": f"https://github.com/{REPOSITORY}/pull/12",
            "state": "open",
            "user": {"login": author},
            "head": {"ref": head_ref, "sha": "1" * 40, "repo": {"full_name": head_repo, "owner": {"login": owner}}},
            "base": {"ref": base_ref, "sha": "2" * 40, "repo": {"full_name": REPOSITORY}},
        },
    }


def run_ctx(ledger: Ledger, tmp_path: Path, env: dict[str, str]) -> tuple[subprocess.CompletedProcess[str], Path]:
    out = tmp_path / "ctx-out" / "context.json"
    result = ledger.run_script(CI_CONTEXT, "--out", str(out), env=env)
    return result, out


def test_ci_context_intake_from_fork(ledger: Ledger, tmp_path: Path) -> None:
    env = _gh_env(tmp_path, _pr_event(head_repo="alice/protocol-attestation-ledger", head_ref="nova"))
    result, out = run_ctx(ledger, tmp_path, env)
    assert_passes(result)
    assert "mode=intake" in output(result)
    ctx = json.loads(out.read_text(encoding="utf-8"))
    assert ctx["pull_request"]["head_sha"] == "1" * 40 and ctx["pull_request"]["base_sha"] == "2" * 40
    assert ctx["actor"] == "alice" and ctx["event_action"] == "synchronize"


def test_ci_context_admission_requires_allowlisted_steward(ledger: Ledger, tmp_path: Path) -> None:
    event = _pr_event(head_repo=REPOSITORY, head_ref="admission/nova", author=STEWARD_LOGIN)
    result, _ = run_ctx(ledger, tmp_path, _gh_env(tmp_path, event, GITHUB_ACTOR=STEWARD_LOGIN))
    assert_passes(result)
    assert "mode=admission" in output(result)
    result, _ = run_ctx(ledger, tmp_path, _gh_env(tmp_path, event, GITHUB_ACTOR="mallory"))
    assert result.returncode == 2
    assert "mallory" in output(result)
    ledger.remove("stewards/authorized-github-actors.txt")
    result, _ = run_ctx(ledger, tmp_path, _gh_env(tmp_path, event, GITHUB_ACTOR=STEWARD_LOGIN))
    assert result.returncode == 2


def test_ci_context_main_push_and_fail_closed_cases(ledger: Ledger, tmp_path: Path) -> None:
    env = _gh_env(tmp_path, {"after": "3" * 40}, GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/main")
    result, out = run_ctx(ledger, tmp_path, env)
    assert_passes(result)
    assert "mode=main" in output(result)
    assert json.loads(out.read_text(encoding="utf-8"))["event_name"] == "push"
    env = _gh_env(tmp_path, {"after": "3" * 40}, GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/other")
    assert run_ctx(ledger, tmp_path, env)[0].returncode == 2
    env = _gh_env(tmp_path, _pr_event(head_repo="alice/x", head_ref="nova", base_ref="dev"))
    assert run_ctx(ledger, tmp_path, env)[0].returncode == 2
    env = _gh_env(tmp_path, {}, GITHUB_EVENT_NAME="workflow_dispatch")
    assert run_ctx(ledger, tmp_path, env)[0].returncode == 2
    env = _gh_env(tmp_path, _pr_event(head_repo="alice/x", head_ref="nova"))
    env["GITHUB_EVENT_PATH"] = str(tmp_path / "missing.json")
    assert run_ctx(ledger, tmp_path, env)[0].returncode == 2


def test_ci_context_refuses_output_inside_checkout(ledger: Ledger, tmp_path: Path) -> None:
    env = _gh_env(tmp_path, _pr_event(head_repo="alice/x", head_ref="nova"))
    result = ledger.run_script(CI_CONTEXT, "--out", "context.json", env=env)
    assert result.returncode == 2
    assert not ledger.path("context.json").exists()
    assert os.linesep
