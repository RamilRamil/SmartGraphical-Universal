# Phase 1 Data Model: Finding Verdicts

## New persisted entity: FindingVerdict

Table `finding_verdict` (SQLite, added to `schema.sql`):

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | autoincrement |
| `artifact_id` | INTEGER | FK → `artifact(id)` ON DELETE CASCADE |
| `finding_key` | TEXT | stable hash of `_finding_key(finding)` (see below) |
| `status` | TEXT | `false_positive` \| `accepted` |
| `note` | TEXT | optional, default `''` |
| `created_at` | TEXT | ISO timestamp |
| `updated_at` | TEXT | ISO timestamp |

- **UNIQUE(artifact_id, finding_key)** → set-verdict is an upsert.
- Scoped to the **artifact**, not a scan → survives re-scans and scan deletion.
- Absence of a row = `untriaged` (default, fully visible).

## Stable finding key (reused, single source of truth)

- Existing: `_finding_key(finding) = (rule_id, type_name, function_name,
  source_statement|statement, message)` — used by `diff_scans`.
- New: `_finding_key_hash(finding) = sha256("\x00".join(_finding_key(finding)))`.
  Both diff and verdicts derive from `_finding_key`, so they identify the same
  findings (SC-006).

## Enriched finding (additive, for display)

When `get_scan` / `get_findings` return findings, each finding dict gains:

| Field | Meaning |
|-------|---------|
| `finding_key` | the `_finding_key_hash` (so the client can address a verdict) |
| `verdict` | `{ "status": "false_positive" \| "accepted", "note": str }` or `null` |

Existing finding fields are unchanged; consumers that ignore these fields keep
working (Principle VI).

## State transitions

```text
untriaged ──set false_positive──▶ false_positive ──clear──▶ untriaged
untriaged ──set accepted───────▶ accepted        ──clear──▶ untriaged
false_positive ⇄ accepted (set the other status; upsert overwrites)
```

- `false_positive` → hidden by default, excluded from active count and from diff
  `added`/`removed`.
- `accepted` → visible, marked, counted (acknowledged but not noise).
- `untriaged` → default visible.

## Validation rules

- `status` MUST be one of `false_positive`, `accepted` (reject others).
- `artifact_id` MUST exist; setting a verdict for a missing artifact is an error.
- `finding_key` is opaque to the client (server-computed); a verdict for a key
  not present in the current scan is allowed and retained (inert) per US3 #3.
- `note` is free text, length-bounded (e.g. ≤ 2000 chars) to avoid abuse.

## Diff result (additive field)

`diff_scans` result gains `suppressed_count` (number of `false_positive`-verdicted
findings removed from the active `added`/`removed` buckets); existing
`added`/`removed`/`unchanged_count` keep their meaning for non-suppressed findings.
