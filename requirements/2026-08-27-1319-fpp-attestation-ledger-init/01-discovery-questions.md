# Phase 1 — Discovery Questions

Five product-level yes/no questions. Answer `yes` / `no` / `idk` (idk = accept the default).
Served in bulk at user request; answers recorded in order after all five are collected.

## Q1

Should the implementation live in the currently-open local folder (`I:\Dev\Projects\FIDES-ANIMA\fpp-attestation-ledger`), initialized as the git repo that will be pushed to `github.com/FIDES-ANIMA/fpp-attestation-ledger`?

**Default: Yes** — the plan and steward cert source (`.resources/FIDES-keys.txt`) are already here; `.resources/` would be git-ignored or excluded.

## Q2

Should the GitHub repo be public from the moment it is created (rather than private during Phases 1–3 and flipped public after seed entries and CI pass)?

**Default: Yes** — the plan describes a public, append-mostly ledger and Phase 1 says "Create repo (public)"; early history being visible is consistent with the audit-trail ethic.

## Q3

Should the initial launch include both seed entries from §7 (Axiom `accepted` and Hermes `reviewed`/operator-filed), pending confirmation of Axiom's live `fpp_id`?

**Default: Yes** — the plan's Phase 3 seeds both, and having one identity-bound and one operator-filed entry exercises both filing paths from day one.

## Q4

Do you currently have offline access to the FIDES-ANIMA OpenPGP secret key (fingerprint `715E 1821 92C5 46A6 12F8 E6D6 4A9E 2AFF 11CB 1432`) so steward admissions (detached `.asc` + signed merges) can be performed during Phase 3?

**Default: Yes** — Phase 3 cannot complete without it; if No, seeding is blocked and the spec must sequence signing as a later manual step.

## Q5

Should CI enforce the strict lifecycle rule that a first filing of `accepted` is rejected unless `notes` records prior inspection (the "default strict" relaxation described in §4)?

**Default: Yes** — the plan says default strict; the GOVERNANCE.md relaxation (steward may accept first-filing `accepted` when notes record inspection) stays documented but off.
