# Feature Specification: Finding Verdicts (False-Positive / Triage Suppression)

**Feature Branch**: `013-findings-fp-suppression`

**Created**: 2026-06-02

**Status**: Draft

**Input**: Let an auditor record a verdict on a finding (false positive, or accepted) that persists and carries across re-scans, so triage isn't lost and noise can be hidden.

## Context

SmartGraphical surfaces heuristic findings for a human to judge (constitution Principle II). Today that judgment is throwaway: there is no way to mark a finding as a false positive, and every re-scan of the same artifact re-surfaces the same noise. Scans, findings, and a scan-to-scan diff already persist (SQLite + per-scan JSON), and the diff already computes a stable per-finding key. This feature adds a thin, persistent **triage layer** on top — a verdict per finding — without touching rules, parsing, or how findings are produced.

Scope is the web UI and the `web_api` facade. Verdicts are recorded by the auditor only; the tool never suppresses a finding on its own.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Record a verdict on a finding (Priority: P1)

From a finding, the auditor sets a verdict — **false positive** or **accepted** (acknowledged) — with an optional short note. The verdict is saved and visible on return.

**Why this priority**: This is the core capability; nothing else works without persisting a verdict. It is independently valuable: even just recording verdicts gives an audit trail of what was reviewed.

**Independent Test**: Set a finding to "false positive" with a note; reload the scan and confirm the verdict and note are still shown.

**Acceptance Scenarios**:

1. **Given** a finding with no verdict, **When** the auditor marks it "false positive" with a note, **Then** the verdict and note persist and are shown on that finding.
2. **Given** a finding marked "accepted", **When** the auditor reloads, **Then** it still shows "accepted".
3. **Given** a verdict exists, **When** the auditor opens the same finding, **Then** the current verdict and note are pre-filled / displayed.

---

### User Story 2 - Hide suppressed noise, keep the signal (Priority: P1)

Findings marked **false positive** are hidden from the findings list by default and excluded from the active findings count; they are reachable via a "N suppressed" toggle. Findings marked **accepted** stay visible but are visually marked.

**Why this priority**: The point of triage is a quieter list on the next look. Pairs with US1 as the MVP.

**Acceptance Scenarios**:

1. **Given** 10 findings with 3 marked false-positive, **When** the findings list renders, **Then** it shows 7 by default and the active count reads 7, with a "3 suppressed" affordance.
2. **Given** the "show suppressed" toggle is on, **When** the list renders, **Then** all 10 are shown, the 3 suppressed clearly marked.
3. **Given** a finding marked "accepted", **When** the list renders by default, **Then** it remains visible with an "accepted" marker.
4. **Given** the confidence filter is also applied, **When** both are active, **Then** suppression and the confidence filter compose without conflict.

---

### User Story 3 - Verdicts survive a re-scan (Priority: P1)

A verdict is tied to a **stable finding identity** and scoped to the artifact, so re-running the scan on the same artifact keeps the verdict — the auditor does not re-triage the same finding.

**Why this priority**: Without persistence across re-scans, suppression is useless (the noise returns every run). This is what makes triage durable.

**Independent Test**: Mark a finding false-positive; re-run the scan on the same artifact; confirm the same finding is still suppressed in the new scan without re-marking.

**Acceptance Scenarios**:

1. **Given** a finding marked false-positive in scan A, **When** the artifact is re-scanned (scan B) and the same finding recurs, **Then** it is suppressed in scan B automatically.
2. **Given** a finding's location shifts but its identity key is unchanged, **When** re-scanned, **Then** the verdict still applies.
3. **Given** a finding that no longer occurs after a re-scan, **When** scan B renders, **Then** no error occurs and the stale verdict is simply inert (retained for if it recurs).

---

### User Story 4 - Diff respects verdicts (Priority: P2)

The scan-to-scan diff does not resurface a finding already marked false-positive as "added" noise; suppressed findings are excluded from or annotated in the diff buckets.

**Acceptance Scenarios**:

1. **Given** a finding marked false-positive present in both scans, **When** the diff is computed, **Then** it is not reported as newly "added".
2. **Given** a suppressed finding, **When** the diff renders, **Then** it is excluded from the active added/removed buckets or clearly annotated as suppressed.

---

### User Story 5 - Change or clear a verdict (Priority: P3)

The auditor can change a verdict (e.g., false-positive → accepted), clear it back to untriaged, and edit the note.

**Acceptance Scenarios**:

1. **Given** a finding marked false-positive, **When** the auditor clears the verdict, **Then** it returns to the default (visible, untriaged).
2. **Given** a verdict with a note, **When** the auditor edits the note, **Then** the new note persists.

### Edge Cases

- Two findings that resolve to the **same** stable key (genuinely indistinguishable) share one verdict — acceptable and documented.
- A verdict whose finding no longer appears in the latest scan is retained (inert) so it re-applies if the finding returns; it must not break rendering.
- Verdicts are **per-artifact**: the same finding text on a *different* artifact is not suppressed.
- Deleting a scan must not delete verdicts (they belong to the artifact, not a single scan); deleting an artifact may remove its verdicts.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: An auditor MUST be able to set a finding's verdict to one of: untriaged (default), false positive, accepted — with an optional free-text note.
- **FR-002**: A verdict MUST persist across sessions and be retrievable for the finding it applies to.
- **FR-003**: A verdict MUST be keyed to a stable finding identity and scoped to the artifact, using the **same stable key the existing scan diff uses**, so a recurring finding keeps its verdict across re-scans (single source of truth for identity).
- **FR-004**: By default, false-positive findings MUST be hidden from the findings list and excluded from the active findings count, with an affordance to reveal them; accepted findings MUST remain visible but marked.
- **FR-005**: The scan-to-scan diff MUST NOT report a false-positive-verdicted finding as newly added; suppressed findings MUST be excluded from or annotated in the diff.
- **FR-006**: The auditor MUST be able to change or clear a verdict and edit its note.
- **FR-007**: The system MUST only record verdicts the auditor sets; it MUST NOT assign or change a verdict automatically.
- **FR-008**: Verdict storage MUST be additive — existing findings, graph, history, and diff outputs continue to work for callers that ignore verdicts; deleting a scan MUST NOT delete the artifact's verdicts.
- **FR-009**: The feature MUST NOT modify rules, parsing, adapters, or how findings are generated.

### Key Entities

- **Finding verdict**: a record of `{ artifact, stable finding key, status (untriaged | false_positive | accepted), note, updated_at }`. Scoped to an artifact; one verdict per (artifact, finding key).
- **Stable finding key** (existing concept): the composite identity the diff already derives from a finding's fields; reused here verbatim.
- **Finding** / **Scan** / **Artifact** (existing): unchanged; findings are annotated with their verdict for display.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An auditor can mark a finding false-positive and, on the next scan of the same artifact, that finding is suppressed automatically with zero re-marking.
- **SC-002**: With N findings of which K are false-positive, the default findings view shows exactly N−K and the active count reads N−K, with the K reachable via one toggle.
- **SC-003**: A verdict survives at least one re-scan and one app restart (persisted), verified end to end.
- **SC-004**: The diff of two scans of the same artifact never lists a false-positive-verdicted finding as "added".
- **SC-005**: All existing findings/graph/history/diff behavior is unchanged for the no-verdict case (no regression in current tests).
- **SC-006**: Suppression and diff agree because both use the one stable finding key (a finding suppressed in the list is the same identity the diff matches).

## Assumptions

- Single local researcher / no multi-user auth (matches the current local-tool model); "the auditor" is the local user. No per-user verdicts in v1.
- The existing diff stable key is sufficiently stable to identify a recurring finding; if it proves too coarse/fine, refining it is a separate change (this feature reuses whatever it is, keeping one source of truth).
- Verdicts are per-artifact; cross-artifact or project-wide suppression is out of scope.
- Default verdict for any finding without a record is "untriaged" (fully visible).

## Non-Goals

- Rule-level auto-suppression or learning suppression rules from verdicts.
- Project-wide / glob / path-based suppression rules.
- Sharing verdicts across different artifacts or multi-user verdict attribution.
- Severity/confidence re-scoring.
- CLI verdict management (web UI + `web_api` facade first).
- Changing how findings are produced (rules/parsing).
