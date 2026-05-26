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
/** Vertical gap between state / modifier / function / event bands. */
export const REGION_GAP = 72;

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
};

export type GridPosition = { x: number; y: number };

type TierRegion = {
  tier: number;
  cells: LayoutCell[];
  cols: number;
  rowCount: number;
  height: number;
};

export function tierForGroup(group: string | undefined): number | null {
  if (!group) return null;
  return TIER_BY_GROUP[group] ?? null;
}

export function colsForTier(tier: number, cellCount: number): number {
  if (cellCount <= 0) return 1;
  if (tier === TIER_FUNCTION) {
    return Math.max(1, Math.ceil(Math.sqrt(cellCount * 1.35)));
  }
  if (tier === TIER_STATE || tier === TIER_MODIFIER) {
    return Math.min(cellCount, Math.max(3, Math.ceil(Math.sqrt(cellCount))));
  }
  return Math.max(1, Math.ceil(Math.sqrt(cellCount)));
}

function buildTierRegions(cells: LayoutCell[]): TierRegion[] {
  const byTier = new Map<number, LayoutCell[]>();
  for (const cell of cells) {
    const bucket = byTier.get(cell.tier) ?? [];
    bucket.push(cell);
    byTier.set(cell.tier, bucket);
  }

  const regions: TierRegion[] = [];
  for (const tier of TIER_ORDER) {
    const row = byTier.get(tier);
    if (!row?.length) continue;
    row.sort((a, b) => a.sortKey.localeCompare(b.sortKey));
    const cols = colsForTier(tier, row.length);
    const rowCount = Math.ceil(row.length / cols);
    const height = rowCount * CELL_HEIGHT + Math.max(0, rowCount - 1) * ROW_GAP;
    regions.push({ tier, cells: row, cols, rowCount, height });
  }
  return regions;
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

/** Place cells in separated horizontal bands per semantic tier. */
export function gridPositionsForCells(cells: LayoutCell[]): Map<string, GridPosition> {
  const out = new Map<string, GridPosition>();
  const regions = buildTierRegions(cells);
  if (regions.length === 0) return out;

  const totalHeight =
    regions.reduce((sum, r) => sum + r.height, 0) +
    Math.max(0, regions.length - 1) * REGION_GAP;
  let yTop = -totalHeight / 2;

  for (const region of regions) {
    const gridW = region.cols * CELL_WIDTH + Math.max(0, region.cols - 1) * COL_GAP;
    region.cells.forEach((cell, index) => {
      const col = index % region.cols;
      const row = Math.floor(index / region.cols);
      const x =
        col * (CELL_WIDTH + COL_GAP) -
        gridW / 2 +
        CELL_WIDTH / 2;
      const y =
        yTop +
        row * (CELL_HEIGHT + ROW_GAP) +
        CELL_HEIGHT / 2;
      out.set(cell.anchorId, { x, y });
    });
    yTop += region.height + REGION_GAP;
  }
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
    });
  });
  return cells;
}

export function assignTieredGridSeeds(compound: NodeSingular): void {
  const cells = collectLayoutCells(compound);
  const positions = gridPositionsForCells(cells);
  positions.forEach((pos, id) => {
    const node = compound.cy().getElementById(id);
    if (node.nonempty()) {
      node.position(pos);
    }
  });
}

function tierNodeClosure(compound: NodeSingular, tier: number): NodeCollection {
  const cy = compound.cy();
  let collection = cy.collection();
  for (const cell of collectLayoutCells(compound)) {
    if (cell.tier !== tier) continue;
    const anchor = cy.getElementById(cell.anchorId);
    if (anchor.empty()) continue;
    collection = collection.union(anchor.union(anchor.descendants()));
  }
  return collection;
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
  for (const tier of TIER_ORDER) {
    const nodes = tierNodeClosure(compound, tier);
    if (nodes.length > 1) {
      nodes.layout(interiorFcoseOptions()).run();
    }
  }
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

/** Grouped tier bands + per-tier fcose inside; spread seeds + force between compounds. */
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
}
