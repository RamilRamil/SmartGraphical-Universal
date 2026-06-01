# Feature Specification: Findings Overlay on the Interactive Graph

**Feature Branch**: `012-findings-graph-overlay`

**Created**: 2026-06-01

**Status**: Draft

**Input**: Fuse the two product pillars — heuristic findings and the interactive code graph — so an auditor can see WHERE in the structure each concern lives, and move between a finding and its place on the graph in one click.

## Context

SmartGraphical's two pillars are currently disconnected in the UI: the Findings tab lists concerns, the Graph tab draws the structure, but neither references the other. Findings already carry locating evidence (the owning type, function, and line numbers) and graph nodes already have stable per-entity identity, so the data needed to connect them exists. This feature is the realization of constitution Principle V (Two Pillars Stay Connected). It changes no rules and no finding content — only the correlation and its presentation.

Scope is the web Cytoscape graph on scans run with task `all` (the only scans that produce a graph today).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - See where findings cluster on the graph (Priority: P1)

On the Graph tab, every node that owns one or more findings is visually marked: a count of its findings and a color that reflects the **highest confidence** among them. An auditor scanning the graph immediately sees which contracts, functions, and state entities carry concerns and how strong each is.

**Why this priority**: This is the core value of fusing the pillars — turning a flat list into a spatial map of risk. It stands alone: even with nothing else, an auditor gains "where is the risk concentrated?"

**Independent Test**: Load a scan with findings; confirm the nodes whose entities own findings show a count and a confidence-derived color, and nodes without findings do not.

**Acceptance Scenarios**:

1. **Given** a task `all` scan with findings on a function, **When** the Graph tab renders, **Then** that function's node shows a finding-count indicator and a color matching its highest-confidence finding.
2. **Given** a node owns findings of mixed confidence (e.g., one `low`, one `high`), **When** it is marked, **Then** the color reflects `high` and the count reflects the total (2).
3. **Given** a node owns no findings, **When** the graph renders, **Then** it carries no finding indicator.
4. **Given** confidence is only `low` on a node, **When** it is marked, **Then** the styling is visibly more muted than a `high` node (confidence is not overstated — Principle II).

---

### User Story 2 - Jump from a finding to its place on the graph (Priority: P1)

From the Findings tab, the auditor selects a finding and is taken to that finding's node on the Graph tab (the view focuses and highlights it). If the finding's evidence cannot be resolved to a node, the UI says so explicitly.

**Why this priority**: "Show me this finding in the structure" is the most common auditor question and the most direct payoff of the connection. Pairs with US1 as the MVP.

**Independent Test**: Click a finding that maps to a known function; confirm the Graph tab opens with that node focused/highlighted. Click a finding with unresolvable evidence; confirm an explicit "not locatable on the graph" message.

**Acceptance Scenarios**:

1. **Given** a finding whose evidence names a type and function present in the graph, **When** the auditor activates "show on graph", **Then** the Graph tab is shown with that node centered and highlighted.
2. **Given** a finding whose evidence resolves only to a type (no function), **When** activated, **Then** the type/container node is focused.
3. **Given** a finding whose evidence has no resolvable target, **When** activated, **Then** the UI shows an explicit "this finding could not be located on the graph" message and does not silently no-op.
4. **Given** the scan has no graph (single-task scan), **When** viewing findings, **Then** the "show on graph" affordance is absent or disabled with a hint, consistent with the existing graph-availability rule.

---

### User Story 3 - Filter the graph to the suspicious surface (Priority: P2)

A toggle on the Graph tab restricts the canvas to nodes that own findings (optionally including their immediate neighbors), so the auditor can strip a large graph down to just the area under concern.

**Why this priority**: High value on large contracts/bundles, but secondary to seeing and navigating findings (US1/US2).

**Acceptance Scenarios**:

1. **Given** a graph with some nodes owning findings, **When** the auditor enables "only nodes with findings", **Then** only those nodes (and edges among them) remain visible.
2. **Given** the same, **When** the auditor also enables "include neighbors", **Then** directly connected nodes are shown too.
3. **Given** no node owns findings, **When** the filter is enabled, **Then** the UI shows an explicit empty state rather than a blank canvas.

---

### User Story 4 - See a node's findings from the graph (Priority: P3)

Selecting a node on the graph lists that node's findings in the side details panel (the reverse of US2).

**Acceptance Scenarios**:

1. **Given** a node that owns findings, **When** it is selected, **Then** the details panel lists those findings (title, category, confidence) and can open each.
2. **Given** a node that owns none, **When** selected, **Then** the panel states it has no findings.

### Edge Cases

- A finding maps to **multiple** nodes (e.g., a name that is ambiguous): the count is attributed to each resolved node; US2 focuses the best/first match and indicates multiplicity.
- The graph node id scheme differs by language (Solidity `type:`/`function:`, C `tile:`/`function:`): correlation must work for all supported languages via the same entity identity the graph already uses.
- Findings whose evidence has line numbers but no resolvable type/function are counted as **unmapped** and surfaced (US2 #3), never dropped.
- Confidence values outside the known set (`low`/`medium`/`high`) fall back to the most muted styling.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST associate each finding with the graph node(s) representing the entity its evidence identifies (type, function, or state entity), using the same entity identity the graph already uses.
- **FR-002**: Graph nodes that own one or more findings MUST be visually distinguishable, showing a finding count and a styling derived from the highest confidence among their findings.
- **FR-003**: Confidence MUST be represented honestly: a node whose findings are only low-confidence MUST be visibly less prominent than one with high-confidence findings (no overstatement).
- **FR-004**: From the findings view, a user MUST be able to navigate to a finding's node on the graph, with that node focused and highlighted.
- **FR-005**: When a finding cannot be resolved to any graph node, the system MUST tell the user explicitly rather than failing silently.
- **FR-006**: Users MUST be able to filter the graph to only nodes that own findings, with an option to include their immediate neighbors, and MUST see an explicit empty state when none qualify.
- **FR-007**: Selecting a graph node MUST reveal that node's findings (or state that it has none).
- **FR-008**: The correlation MUST work across all supported languages (Solidity, C, Rust/Stellar) without per-language special-casing in the user experience.
- **FR-009**: Any data added to connect findings and the graph MUST be additive and not break existing consumers of the findings list or the graph payload (stable contract).
- **FR-010**: The feature applies to scans that produce a graph (task `all`); for scans without a graph, the navigation affordance MUST be absent or disabled with a hint.

### Key Entities

- **Finding-to-node correlation**: the mapping from a finding (via its evidence: type, function, state entity) to the graph node id(s) it belongs to; includes an "unmapped" outcome.
- **Node finding summary**: per node, the count of owned findings and the highest confidence among them (drives styling/badging).
- **Finding** / **FindingEvidence** (existing): source of `type_name`, `function_name`, line numbers, `category`, `confidence`. Unchanged by this feature.
- **Graph node** (existing): the Cytoscape node with stable per-entity id and `type_name`/label. Unchanged in identity.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For a scan with findings, 100% of findings whose evidence names an entity present in the graph are attributed to the correct node; findings that cannot be resolved are reported as unmapped (0 silently dropped).
- **SC-002**: An auditor can go from a listed finding to its highlighted node on the graph in a single action.
- **SC-003**: On a graph, an auditor can identify every node that owns findings, and its relative confidence, without opening the findings list.
- **SC-004**: Enabling "only nodes with findings" reduces the visible graph to exactly the finding-owning nodes (plus neighbors when chosen), verified on a multi-finding scan.
- **SC-005**: Existing findings-list and graph consumers continue to work unchanged (no regression in current tests).
- **SC-006**: Correlation behaves correctly for at least one Solidity, one C, and one Rust/Stellar scan fixture.

## Assumptions

- Findings' evidence (`type_name`, `function_name`) is the correlation key; its quality is whatever the rules emit today (this feature does not improve evidence inference, only consumes it).
- The graph remains task `all`-only; single-task scans are out of scope for the overlay.
- "Highest confidence" ordering is `high` > `medium` > `low`; unknown values are treated as the lowest.
- English UI labels; ASCII identifiers in code.

## Non-Goals

- The CLI graphviz renderer overlay (web Cytoscape only in v1).
- Any change to rules, finding content, evidence inference, or confidence levels.
- New finding types or severity beyond the existing confidence levels.
- Graphs for single-task scans.
- Changing the existing graph layout engine or node-id scheme.
