import type { Core, NodeCollection, NodeSingular } from "cytoscape";

/** Semantic bands inside a contract compound (top to bottom). */
export const TIER_STATE = 0;
export const TIER_MODIFIER = 1;
export const TIER_FUNCTION = 2;
export const TIER_EVENT = 3;

export const TIER_ORDER = [
  TIER_STATE,
  TIER_MODIFIER,
  TIER_FUNCTION,
  TIER_EVENT,
] as const;

export const CELL_WIDTH = 98;
export const CELL_HEIGHT = 76;
export const COL_GAP = 32;
export const ROW_GAP = 28;
/** Vertical gap between state / function / event bands. */
export const REGION_GAP = 72;
/** Gap between modifier corner column and main tier content. */
export const MODIFIER_CORNER_GAP = 40;
/** Max functions per row before splitting into two sub-rows. */
export const MAX_FUNCTIONS_PER_ROW = 6;
/** Gap between function sub-rows and the state line. */
export const FUNCTION_BAND_GAP = 36;
/** Gap between main content and the side event column. */
export const EVENT_SIDE_GAP = 48;
/** Added to function degree when is_entrypoint (pulls node toward state band). */
export const ENTRYPOINT_DEGREE_BONUS = 8;

const COMPOUND_ROOT_GROUPS = new Set(["type", "tile"]);

const TIER_BY_GROUP: Record<string, number> = {
  state: TIER_STATE,
  workspace: TIER_STATE,
  modifier: TIER_MODIFIER,
  function: TIER_FUNCTION,
  modifier_ring: TIER_FUNCTION,
  event: TIER_EVENT,
  custom_error: TIER_EVENT,
};

export type LayoutCell = {
  anchorId: string;
  tier: number;
  sortKey: string;
  visibility?: string;
  isEntrypoint?: boolean;
};

export type LayoutEdgeHint = {
  source: string;
  target: string;
};

export type GridPosition = { x: number; y: number };

export function tierForGroup(group: string | undefined): number | null {
  if (!group) return null;
  return TIER_BY_GROUP[group] ?? null;
}

export function colsForTier(tier: number, cellCount: number): number {
  if (cellCount <= 0) return 1;
  if (tier === TIER_STATE) {
    return cellCount;
  }
  if (tier === TIER_MODIFIER) {
    return 1;
  }
  return Math.max(1, Math.ceil(Math.sqrt(cellCount)));
}

export function isAboveStateVisibility(visibility: string | undefined): boolean {
  const v = (visibility || "").toLowerCase();
  return v === "public" || v === "external";
}

export function computeFunctionDegrees(
  functionIds: ReadonlySet<string>,
  edgeHints: readonly LayoutEdgeHint[],
): Map<string, number> {
  const degrees = new Map<string, number>();
  for (const id of functionIds) {
    degrees.set(id, 0);
  }
  for (const edge of edgeHints) {
    if (functionIds.has(edge.source)) {
      degrees.set(edge.source, (degrees.get(edge.source) ?? 0) + 1);
    }
    if (functionIds.has(edge.target)) {
      degrees.set(edge.target, (degrees.get(edge.target) ?? 0) + 1);
    }
  }
  return degrees;
}

/** Edge degree plus entrypoint bonus for sandwich row ordering. */
export function effectiveFunctionDegrees(
  functions: LayoutCell[],
  edgeHints: readonly LayoutEdgeHint[],
): Map<string, number> {
  const functionIds = new Set(functions.map((f) => f.anchorId));
  const degrees = computeFunctionDegrees(functionIds, edgeHints);
  for (const cell of functions) {
    if (cell.isEntrypoint) {
      degrees.set(
        cell.anchorId,
        (degrees.get(cell.anchorId) ?? 0) + ENTRYPOINT_DEGREE_BONUS,
      );
    }
  }
  return degrees;
}

function compareCellsByDegree(
  a: LayoutCell,
  b: LayoutCell,
  degrees: Map<string, number>,
): number {
  const da = degrees.get(a.anchorId) ?? 0;
  const db = degrees.get(b.anchorId) ?? 0;
  if (db !== da) return db - da;
  return a.sortKey.localeCompare(b.sortKey);
}

/**
 * Wrap functions into a balanced grid (~sqrt(n) columns) so large bands stay
 * compact instead of stretching into one or two very wide rows. Cells are
 * degree-ordered (highest first), so the leading row is the busiest.
 *
 * Bands at or below MAX_FUNCTIONS_PER_ROW stay a single row.
 */
export function splitFunctionRows(
  cells: LayoutCell[],
  degrees: Map<string, number>,
): LayoutCell[][] {
  const ordered = [...cells].sort((a, b) => compareCellsByDegree(a, b, degrees));
  if (ordered.length <= MAX_FUNCTIONS_PER_ROW) {
    return [ordered];
  }
  const cols = colsForTier(TIER_FUNCTION, ordered.length);
  const rows: LayoutCell[][] = [];
  for (let i = 0; i < ordered.length; i += cols) {
    rows.push(ordered.slice(i, i + cols));
  }
  return rows;
}

function placeRowCentered(
  cells: LayoutCell[],
  centerY: number,
  out: Map<string, GridPosition>,
): void {
  if (cells.length === 0) return;
  const gridW =
    cells.length * CELL_WIDTH + Math.max(0, cells.length - 1) * COL_GAP;
  cells.forEach((cell, index) => {
    const x =
      index * (CELL_WIDTH + COL_GAP) - gridW / 2 + CELL_WIDTH / 2;
    out.set(cell.anchorId, { x, y: centerY });
  });
}

function placeEventsOnSide(
  events: LayoutCell[],
  main: Map<string, GridPosition>,
  out: Map<string, GridPosition>,
): void {
  if (events.length === 0) return;
  const sorted = [...events].sort((a, b) => a.sortKey.localeCompare(b.sortKey));

  let maxX = 0;
  let minY = 0;
  let maxY = 0;
  let hasMain = false;
  for (const pos of main.values()) {
    hasMain = true;
    maxX = Math.max(maxX, pos.x);
    minY = Math.min(minY, pos.y);
    maxY = Math.max(maxY, pos.y);
  }

  const baseX = hasMain
    ? maxX + CELL_WIDTH / 2 + EVENT_SIDE_GAP + COL_GAP
    : CELL_WIDTH;
  const midY = hasMain ? (minY + maxY) / 2 : 0;
  const rowStep = CELL_HEIGHT + ROW_GAP;

  sorted.forEach((cell, index) => {
    const offset = (index - (sorted.length - 1) / 2) * rowStep;
    out.set(cell.anchorId, {
      x: baseX + CELL_WIDTH / 2,
      y: midY + offset,
    });
  });
}

function layoutFunctionBandAbove(
  cells: LayoutCell[],
  degrees: Map<string, number>,
  stateTopY: number,
  out: Map<string, GridPosition>,
): void {
  const rows = splitFunctionRows(cells, degrees);
  let yBottom = stateTopY - FUNCTION_BAND_GAP;
  for (let i = rows.length - 1; i >= 0; i -= 1) {
    const row = rows[i]!;
    yBottom -= CELL_HEIGHT;
    placeRowCentered(row, yBottom + CELL_HEIGHT / 2, out);
    if (i > 0) yBottom -= ROW_GAP;
  }
}

function layoutFunctionBandBelow(
  cells: LayoutCell[],
  degrees: Map<string, number>,
  stateBottomY: number,
  out: Map<string, GridPosition>,
): void {
  const rows = splitFunctionRows(cells, degrees);
  let yTop = stateBottomY + FUNCTION_BAND_GAP;
  for (const row of rows) {
    placeRowCentered(row, yTop + CELL_HEIGHT / 2, out);
    yTop += CELL_HEIGHT + ROW_GAP;
  }
}

/** State line at y=0; public/external above; other functions below; events on the right. */
export function gridPositionsForMainCells(
  cells: LayoutCell[],
  edgeHints: readonly LayoutEdgeHint[] = [],
): Map<string, GridPosition> {
  const out = new Map<string, GridPosition>();
  const states = cells
    .filter((c) => c.tier === TIER_STATE)
    .sort((a, b) => a.sortKey.localeCompare(b.sortKey));
  const functions = cells.filter((c) => c.tier === TIER_FUNCTION);
  const events = cells.filter((c) => c.tier === TIER_EVENT);

  const degrees = effectiveFunctionDegrees(functions, edgeHints);

  const aboveFns = functions.filter((f) => isAboveStateVisibility(f.visibility));
  const belowFns = functions.filter((f) => !isAboveStateVisibility(f.visibility));

  const stateY = 0;
  placeRowCentered(states, stateY, out);

  const stateTopY = stateY - CELL_HEIGHT / 2;
  const stateBottomY = stateY + CELL_HEIGHT / 2;

  if (aboveFns.length > 0) {
    layoutFunctionBandAbove(aboveFns, degrees, stateTopY, out);
  }
  if (belowFns.length > 0) {
    layoutFunctionBandBelow(belowFns, degrees, stateBottomY, out);
  }
  placeEventsOnSide(events, out, out);

  return out;
}

function gridPositionsForModifierCorner(
  modifiers: LayoutCell[],
  main: Map<string, GridPosition>,
): Map<string, GridPosition> {
  const out = new Map<string, GridPosition>();
  if (modifiers.length === 0) return out;

  const sorted = [...modifiers].sort((a, b) => a.sortKey.localeCompare(b.sortKey));
  const colStep = CELL_WIDTH + COL_GAP;
  const rowStep = CELL_HEIGHT + ROW_GAP;

  let anchorMinX = 0;
  let topEdgeY = 0;
  if (main.size > 0) {
    let minX = Infinity;
    let minY = Infinity;
    for (const pos of main.values()) {
      minX = Math.min(minX, pos.x);
      minY = Math.min(minY, pos.y);
    }
    anchorMinX = minX;
    topEdgeY = minY - CELL_HEIGHT / 2;
  }

  const blockW = colStep;
  const baseX =
    anchorMinX - MODIFIER_CORNER_GAP - blockW / 2 - CELL_WIDTH / 2;

  sorted.forEach((cell, index) => {
    out.set(cell.anchorId, {
      x: baseX,
      y: topEdgeY + index * rowStep + CELL_HEIGHT / 2,
    });
  });
  return out;
}

/** Contract compounds that own interior layout (exclude type nested under tile). */
export function pickInteriorLayoutRootIds(
  nodes: ReadonlyArray<{ id: string; group: string; parent?: string }>,
): string[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const hasChild = new Set<string>();
  for (const n of nodes) {
    if (n.parent) hasChild.add(n.parent);
  }

  const roots: string[] = [];
  for (const n of nodes) {
    if (!COMPOUND_ROOT_GROUPS.has(n.group)) continue;
    if (!hasChild.has(n.id)) continue;
    if (n.parent) {
      const parent = byId.get(n.parent);
      if (parent && COMPOUND_ROOT_GROUPS.has(parent.group)) continue;
    }
    roots.push(n.id);
  }
  return roots.sort();
}

/**
 * Sandwich layout + modifier corner; optional edge hints for function degree ordering.
 */
export function gridPositionsForCells(
  cells: LayoutCell[],
  edgeHints: readonly LayoutEdgeHint[] = [],
): Map<string, GridPosition> {
  const modifiers = cells.filter((c) => c.tier === TIER_MODIFIER);
  const mainCells = cells.filter((c) => c.tier !== TIER_MODIFIER);
  const out = gridPositionsForMainCells(mainCells, edgeHints);
  const corner = gridPositionsForModifierCorner(modifiers, out);
  corner.forEach((pos, id) => out.set(id, pos));
  return out;
}

export function countCircularOverlaps(
  positions: Map<string, GridPosition>,
  radius: number,
): number {
  const ids = [...positions.keys()];
  let overlaps = 0;
  for (let i = 0; i < ids.length; i += 1) {
    const a = positions.get(ids[i]!);
    if (!a) continue;
    for (let j = i + 1; j < ids.length; j += 1) {
      const b = positions.get(ids[j]!);
      if (!b) continue;
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      const minDist = radius * 2;
      if (dx * dx + dy * dy < minDist * minDist) overlaps += 1;
    }
  }
  return overlaps;
}

export type OuterCompoundSlot = {
  id: string;
  width: number;
  height: number;
  sortKey: string;
};

/** Spread top-level compounds on a grid before outer force layout (avoids (0,0) collapse). */
export function gridPositionsForOuterCompounds(
  slots: OuterCompoundSlot[],
  padding = 72,
  maxRowWidth = 3200,
): Map<string, GridPosition> {
  const out = new Map<string, GridPosition>();
  if (slots.length === 0) return out;

  const sorted = [...slots].sort((a, b) => a.sortKey.localeCompare(b.sortKey));
  let xCursor = 0;
  let rowY = 0;
  let rowHeight = 0;

  for (const slot of sorted) {
    const slotW = Math.max(slot.width, 140) + padding;
    const slotH = Math.max(slot.height, 140) + padding;
    if (xCursor > 0 && xCursor + slotW > maxRowWidth) {
      xCursor = 0;
      rowY += rowHeight;
      rowHeight = 0;
    }
    out.set(slot.id, {
      x: xCursor + slotW / 2,
      y: rowY + slotH / 2,
    });
    xCursor += slotW;
    rowHeight = Math.max(rowHeight, slotH);
  }
  return out;
}

const OUTER_LAYOUT_GROUPS = new Set(["type", "tile", "external", "external_import"]);

export function isOuterLayoutNode(group: string | undefined): boolean {
  return Boolean(group && OUTER_LAYOUT_GROUPS.has(group));
}

function layoutAnchorForChild(child: NodeSingular): NodeSingular {
  if (child.data("group") !== "modifier_ring") return child;
  let cur: NodeSingular = child;
  while (cur.children().length > 0) {
    const nested = cur.children()[0];
    if (!nested) break;
    if (nested.data("group") === "modifier_ring") {
      cur = nested;
      continue;
    }
    return cur;
  }
  return cur;
}

function collectLayoutCells(compound: NodeSingular): LayoutCell[] {
  const cells: LayoutCell[] = [];
  compound.children().forEach((child) => {
    const group = child.data("group") as string | undefined;
    const tier = tierForGroup(group);
    if (tier === null) return;
    const anchor = layoutAnchorForChild(child);
    cells.push({
      anchorId: anchor.id(),
      tier,
      sortKey: (anchor.data("label") as string | undefined) ?? anchor.id(),
      visibility: anchor.data("visibility") as string | undefined,
      isEntrypoint: Boolean(anchor.data("is_entrypoint")),
    });
  });
  return cells;
}

function collectInteriorEdgeHints(
  compound: NodeSingular,
  anchorIds: ReadonlySet<string>,
): LayoutEdgeHint[] {
  const hints: LayoutEdgeHint[] = [];
  compound.cy().edges().forEach((edge) => {
    const source = edge.source().id();
    const target = edge.target().id();
    if (anchorIds.has(source) && anchorIds.has(target)) {
      hints.push({ source, target });
    }
  });
  return hints;
}

export function assignTieredGridSeeds(
  compound: NodeSingular,
  center: GridPosition = { x: 0, y: 0 },
): void {
  const cells = collectLayoutCells(compound);
  const anchorIds = new Set(cells.map((c) => c.anchorId));
  const edgeHints = collectInteriorEdgeHints(compound, anchorIds);
  const positions = gridPositionsForCells(cells, edgeHints);
  positions.forEach((pos, id) => {
    const node = compound.cy().getElementById(id);
    if (node.nonempty()) {
      node.position({ x: center.x + pos.x, y: center.y + pos.y });
    }
  });
}

export function interiorFcoseOptions() {
  return {
    name: "fcose" as const,
    randomize: false,
    animate: false,
    fit: false,
    nodeDimensionsIncludeLabels: true,
    idealEdgeLength: 78,
    nodeRepulsion: 11500,
    edgeElasticity: 0.38,
    nestingFactor: 1.25,
    gravity: 0.12,
    gravityCompound: 1.05,
    gravityRangeCompound: 2.8,
    tile: true,
    tilingPaddingVertical: 20,
    tilingPaddingHorizontal: 20,
    quality: "default" as const,
  };
}

function layoutCompoundInterior(compound: NodeSingular): void {
  assignTieredGridSeeds(compound);
}

function outerLayoutNodes(cy: Core): NodeCollection {
  return cy.nodes().filter((node) => {
    if (node.parent().nonempty()) return false;
    return isOuterLayoutNode(node.data("group") as string | undefined);
  });
}

function assignOuterCompoundSeeds(cy: Core): void {
  const nodes = outerLayoutNodes(cy);
  if (nodes.length <= 1) return;

  const slots: OuterCompoundSlot[] = nodes.map((node) => ({
    id: node.id(),
    width: node.width(),
    height: node.height(),
    sortKey: (node.data("label") as string | undefined) ?? node.id(),
  }));
  const positions = gridPositionsForOuterCompounds(slots);
  positions.forEach((pos, id) => {
    const node = cy.getElementById(id);
    if (node.nonempty()) {
      node.position(pos);
    }
  });
}

export function outerCoseBilkentOptions() {
  return {
    name: "cose-bilkent" as const,
    animate: false,
    nodeDimensionsIncludeLabels: true,
    randomize: false,
    idealEdgeLength: 160,
    nodeRepulsion: 18000,
    gravity: 0.35,
    nestingFactor: 0.12,
    tile: true,
  };
}

function interiorLayoutRoots(cy: Core): NodeCollection {
  return cy.nodes().filter((node) => {
    const group = node.data("group") as string | undefined;
    if (!group || !COMPOUND_ROOT_GROUPS.has(group)) return false;
    if (!node.isParent()) return false;
    const parent = node.parent();
    if (parent.nonempty()) {
      const pg = parent.data("group") as string | undefined;
      if (pg && COMPOUND_ROOT_GROUPS.has(pg)) return false;
    }
    return true;
  });
}

/**
 * Three phases: (1) seed each compound's interior as a balanced tier grid;
 * (2) force-spread the compounds between each other (cose-bilkent); (3) re-impose
 * the deterministic interior grid at each compound's final center, so the force
 * layout's interior reflow does not override the compact arrangement.
 */
export function applyFullGraphTwoPhaseLayout(cy: Core): void {
  const roots = interiorLayoutRoots(cy);
  roots.forEach((compound) => {
    layoutCompoundInterior(compound);
  });

  cy.resize();
  cy.style().update();
  assignOuterCompoundSeeds(cy);
  const outer = outerLayoutNodes(cy);
  if (outer.length > 0) {
    outer.layout(outerCoseBilkentOptions()).run();
  }

  // Phase 3: the outer compound layout (cose-bilkent) reflows interior children,
  // discarding the tier grid. Re-apply the grid at each compound's final center
  // so the interior stays a compact balanced grid in the rendered graph.
  roots.forEach((compound) => {
    assignTieredGridSeeds(compound, {
      x: compound.position("x"),
      y: compound.position("y"),
    });
  });
  cy.style().update();
}
