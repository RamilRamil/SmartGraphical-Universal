# Contract: Verdict API + finding enrichment

All additive. Existing endpoints keep their shape; only new fields/endpoints are
introduced.

## web_api facade (pure, JSON-safe)

```text
set_verdict(artifact_id, finding_key, status, note="") -> verdict dict
clear_verdict(artifact_id, finding_key) -> { "cleared": bool }
list_verdicts(artifact_id) -> [ verdict dict ]
```
- `status` MUST be `false_positive` or `accepted`; else `WebApiError`
  (machine-readable code, consistent with existing facade errors).
- `verdict dict` = `{ artifact_id, finding_key, status, note, created_at, updated_at }`.

## HTTP routes (artifact-scoped)

| Method | Path | Body | Result |
|--------|------|------|--------|
| `PUT` | `/api/artifacts/{artifact_id}/verdicts` | `{ finding_key, status, note? }` | upserted verdict |
| `DELETE` | `/api/artifacts/{artifact_id}/verdicts/{finding_key}` | — | `{ cleared: true }` |
| `GET` | `/api/artifacts/{artifact_id}/verdicts` | — | `{ items: [verdict] }` |

- 404 if the artifact does not exist; 400 on invalid `status`.

## Enriched finding (existing endpoints)

`GET /api/scans/{id}` and `GET /api/scans/{id}/findings` return each finding with
two added fields (Principle VI — additive):

```jsonc
{
  "rule_id": "...", "title": "...", "confidence": "...", "evidences": [...],
  "finding_key": "<sha256 hex>",
  "verdict": { "status": "false_positive", "note": "library false alarm" } // or null
}
```

## Diff (existing endpoint)

`GET /api/scans/{a}/diff/{b}` result gains `suppressed_count`; `added`/`removed`
exclude `false_positive`-verdicted findings:

```jsonc
{ "scan_a_id": 1, "scan_b_id": 2, "artifact_id": 7,
  "added": [...], "removed": [...], "unchanged_count": 4,
  "suppressed_count": 2 }
```

## Behavioral rules

- **R1**: the tool never creates/changes a verdict except via these explicit
  endpoints (Principle II).
- **R2**: `finding_key` is server-computed (`_finding_key_hash`); the client
  echoes it back to address a verdict — it never computes the key itself.
- **R3**: setting a verdict for the same `(artifact_id, finding_key)` upserts
  (overwrites status/note, bumps `updated_at`).
- **R4**: a verdict for a finding absent from the current scan is retained and
  inert; it re-applies if the finding recurs (US3 #3).
- **R5**: deleting a scan leaves verdicts intact; deleting an artifact removes its
  verdicts (FK cascade).
