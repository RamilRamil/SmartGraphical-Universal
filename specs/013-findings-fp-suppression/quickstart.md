# Quickstart: Validate Feature 013 (Finding Verdicts)

Backend: run with `.venv/bin/python` (system python is 3.9). Frontend from
`frontend/` (`npm run dev` against the API for manual checks).

## 1. Persistence + key stability (US1, US3) — Python

```bash
.venv/bin/python -m pytest tests/unit/test_verdict_repository.py \
  tests/unit/test_history_service_verdicts.py -q
```
Asserts: upsert/get/delete + UNIQUE; setting a verdict then reading the scan
annotates that finding; the SAME finding in a re-scan (same `_finding_key`) keeps
its verdict; clearing returns to untriaged.

## 2. Endpoint contract (US1, US5) — Python

```bash
.venv/bin/python -m pytest tests/integration/test_http_verdicts.py -q
```
Asserts: `PUT /api/artifacts/{id}/verdicts` upserts; `GET` lists; `DELETE` clears;
invalid `status` → 400; scan/findings responses now carry `finding_key` + `verdict`.

## 3. Diff respects verdicts (US4) — Python

Mark a finding false-positive on an artifact, run two scans, diff them, and assert
the finding is not in `added` and `suppressed_count` reflects it.

## 4. Manual: hide noise (US2)

- `npm run dev`; open a scan with findings → Findings tab.
- Mark one finding **false positive** (with a note) → it disappears from the list,
  the count drops by one, and a **"1 suppressed"** affordance appears; toggle it to
  reveal the suppressed finding (marked).
- Mark another **accepted** → stays visible with an "accepted" marker.
- Confirm the confidence filter still composes (e.g. filter "high" + suppression).

## 5. Manual: survives re-scan + restart (US3)

- Re-run the scan on the same artifact → the false-positive finding is still
  suppressed without re-marking.
- Restart the app (or `docker compose restart`) → the verdict persists.

## 6. Regression

```bash
.venv/bin/python -m pytest -q          # full suite green; no change for no-verdict findings
cd frontend && npm run test && npm run typecheck
```
Findings/graph/history/diff behave exactly as before when no verdict exists
(Principle VI).
