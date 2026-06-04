# Phase 0 Research: Finding Verdicts

## D1. Stable finding identity for storage (reuse the diff key)

**Decision**: Keep `_finding_key(finding)` (the tuple
`(rule_id, type_name, function_name, source_statement|statement, message)`) as
the single identity. Add a sibling `_finding_key_hash(finding)` =
`sha256("\x00".join(_finding_key(finding))).hexdigest()` for a stable string to
store in SQLite and to match across scans. Diff continues to use the tuple;
verdicts use its hash — both derive from the same `_finding_key`, so they agree.

**Rationale**: FR-003/SC-006 require suppression and diff to use one identity.
The tuple is in-memory only; persistence needs a stable scalar. Hashing the same
tuple keeps a single source of truth with no second scheme.

**Alternatives considered**: a new bespoke key for verdicts — rejected (would
drift from diff, violating SC-006). Storing the raw tuple as JSON — workable but
a fixed-length hash is simpler to index/unique.

## D2. Storage: additive `finding_verdict` table

**Decision**: Add to `schema.sql`:
```sql
CREATE TABLE IF NOT EXISTS finding_verdict (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL,
    finding_key TEXT NOT NULL,         -- _finding_key_hash
    status TEXT NOT NULL,              -- 'false_positive' | 'accepted'
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(artifact_id, finding_key),
    FOREIGN KEY(artifact_id) REFERENCES artifact(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_finding_verdict_artifact ON finding_verdict(artifact_id);
```

**Rationale**: `SqliteStore._apply_schema()` runs `schema.sql` (idempotent) on
every init, so a new `CREATE TABLE IF NOT EXISTS` auto-migrates existing DBs with
no migration framework (Principle VI, additive). `UNIQUE(artifact_id,
finding_key)` makes set-verdict an upsert. `ON DELETE CASCADE` on `artifact`
means deleting an artifact removes its verdicts; deleting a **scan** does not
touch verdicts (they are not linked to scan) — exactly FR-008.

**Alternatives considered**: scan-scoped verdicts — rejected (would not carry
across re-scans, defeating US3). A separate DB/file — rejected (the SQLite store
already exists and is the natural home).

## D3. Where findings get annotated with verdicts

**Decision**: Enrich in `HistoryService.get_scan` and `get_findings` (the two
readers, `:435` / `:466`). After `_read_json` of findings, compute each finding's
`finding_key` hash, look up the artifact's verdicts (one indexed query, built
into a `{finding_key: verdict}` map), and attach `finding_key` + `verdict`
(`{status, note}` or `null`) to each finding dict. The HTTP layer returns them
unchanged.

**Rationale**: single choke point for both the scan-detail and findings
endpoints; keeps the frontend able to send `finding_key` back when setting a
verdict (backend owns key computation — no client-side key logic).

## D4. Diff interaction (FR-005)

**Decision**: In `diff_scans`, after computing `added`/`removed`/`unchanged`,
load the artifact's `false_positive` verdict keys and drop matching findings from
`added` (and `removed`), and expose a `suppressed_count`. Unchanged count stays
as-is. Both scans share the artifact (already asserted), so one verdict set
applies.

**Rationale**: FR-005/SC-004 — a known false positive must not resurface as new
noise. Annotate-or-exclude: excluding from `added`/`removed` with a count is the
simplest honest behavior.

## D5. Repository + facade + routes pattern

**Decision**: New `VerdictRepository` (mirrors `ScanRepository`): `upsert`,
`get_by_artifact(artifact_id) -> list`, `delete(artifact_id, finding_key)`.
`HistoryService` gains `set_verdict / clear_verdict / list_verdicts` (validating
`status in {false_positive, accepted}`). `web_api` adds thin facade wrappers; HTTP
adds `PUT /api/artifacts/{id}/verdicts` (body: finding_key, status, note),
`DELETE /api/artifacts/{id}/verdicts/{finding_key}`, `GET /api/artifacts/{id}/verdicts`.

**Rationale**: consistency with the existing persistence/service/facade/route
layering; verdicts are artifact-scoped so they live under `/artifacts/{id}`.

## D6. Frontend wiring

**Decision**: `Finding` type gains optional `finding_key` and
`verdict: { status, note } | null`. A TanStack mutation sets/clears a verdict
(keyed by artifact_id + finding_key) and invalidates the scan query. `FindingCard`
shows verdict controls (mark false-positive / accepted / clear, + note) and a
marker. `ScanDetailPage` hides `false_positive` findings by default, shows a
"N suppressed" toggle, and the active count excludes them — composing with the
existing confidence filter.

**Rationale**: additive props/fields; reuses the existing query/mutation
patterns; the default-hide is pure client filtering over the enriched findings.

## D7. Testing

**Decision**: Python — `VerdictRepository` unit (upsert/get/delete + unique);
`HistoryService` verdict tests (set/get/clear, **key stable across a simulated
re-scan** so the same finding keeps its verdict, enrichment shape, diff drops a
FP from `added`); HTTP contract test for the verdict endpoints + enriched scan.
Frontend — optional Vitest for the default-hide/count filter helper.

**Rationale**: Principle VII; the key-stability and diff tests directly verify
SC-003/SC-004/SC-006.
