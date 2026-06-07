import { describe, expect, it } from "vitest";

import {
  CELL_HEIGHT,
  CELL_WIDTH,
  colsForTier,
  computeFunctionDegrees,
  countCircularOverlaps,
  effectiveFunctionDegrees,
  ENTRYPOINT_DEGREE_BONUS,
  gridPositionsForCells,
  gridPositionsForMainCells,
  gridPositionsForOuterCompounds,
  isAboveStateVisibility,
  MAX_FUNCTIONS_PER_ROW,
  pickInteriorLayoutRootIds,
  splitFunctionRows,
  TIER_EVENT,
  TIER_FUNCTION,
  TIER_MODIFIER,
  TIER_STATE,
  tierForGroup,
} from "./intraCompoundLayout";

describe("colsForTier", () => {
  it("uses one row for all state cells", () => {
    expect(colsForTier(TIER_STATE, 5)).toBe(5);
    expect(colsForTier(TIER_STATE, 1)).toBe(1);
  });
});

describe("isAboveStateVisibility", () => {
  it("treats public and external as above-state", () => {
    expect(isAboveStateVisibility("public")).toBe(true);
    expect(isAboveStateVisibility("external")).toBe(true);
    expect(isAboveStateVisibility("internal")).toBe(false);
    expect(isAboveStateVisibility("private")).toBe(false);
  });
});

describe("splitFunctionRows", () => {
  it("wraps into a balanced grid (~sqrt cols) above MAX_FUNCTIONS_PER_ROW", () => {
    const cells = Array.from({ length: 8 }, (_, i) => ({
      anchorId: `f${i}`,
      tier: TIER_FUNCTION,
      sortKey: `fn${i}`,
    }));
    const degrees = new Map(cells.map((c, i) => [c.anchorId, i]));
    const rows = splitFunctionRows(cells, degrees);
    const cols = colsForTier(TIER_FUNCTION, 8); // ceil(sqrt(8)) = 3
    expect(cols).toBe(3);
    expect(Math.max(...rows.map((r) => r.length))).toBeLessThanOrEqual(cols);
    expect(rows.flat()).toHaveLength(8);
    expect(rows[0]![0]!.anchorId).toBe("f7"); // highest degree leads
  });

  it("keeps a single row at or below MAX_FUNCTIONS_PER_ROW", () => {
    const cells = Array.from({ length: MAX_FUNCTIONS_PER_ROW }, (_, i) => ({
      anchorId: `f${i}`,
      tier: TIER_FUNCTION,
      sortKey: `fn${i}`,
    }));
    const degrees = new Map(cells.map((c) => [c.anchorId, 0]));
    expect(splitFunctionRows(cells, degrees)).toHaveLength(1);
  });

  it("stays compact for large bands (100 functions -> 10 cols, not one 50-wide strip)", () => {
    const cells = Array.from({ length: 100 }, (_, i) => ({
      anchorId: `f${i}`,
      tier: TIER_FUNCTION,
      sortKey: `fn${String(i).padStart(3, "0")}`,
    }));
    const degrees = new Map(cells.map((c) => [c.anchorId, 0]));
    const rows = splitFunctionRows(cells, degrees);
    expect(Math.max(...rows.map((r) => r.length))).toBe(10);
    expect(rows).toHaveLength(10);
  });
});

describe("tierForGroup", () => {
  it("maps semantic groups to tiers", () => {
    expect(tierForGroup("state")).toBe(TIER_STATE);
    expect(tierForGroup("modifier")).toBe(TIER_MODIFIER);
    expect(tierForGroup("function")).toBe(TIER_FUNCTION);
    expect(tierForGroup("modifier_ring")).toBe(TIER_FUNCTION);
    expect(tierForGroup("event")).toBe(TIER_EVENT);
    expect(tierForGroup("external")).toBeNull();
  });
});

describe("pickInteriorLayoutRootIds", () => {
  it("keeps parentless type compounds", () => {
    const ids = pickInteriorLayoutRootIds([
      { id: "type:A", group: "type" },
      { id: "function:A.f", group: "function", parent: "type:A" },
    ]);
    expect(ids).toEqual(["type:A"]);
  });

  it("skips type nested under tile", () => {
    const ids = pickInteriorLayoutRootIds([
      { id: "tile:tu", group: "tile" },
      { id: "type:A", group: "type", parent: "tile:tu" },
      { id: "function:A.f", group: "function", parent: "type:A" },
    ]);
    expect(ids).toEqual(["tile:tu"]);
  });
});

describe("effectiveFunctionDegrees", () => {
  it("adds entrypoint bonus on top of edge degree", () => {
    const functions = [
      { anchorId: "ep", tier: TIER_FUNCTION, sortKey: "a", isEntrypoint: true },
      { anchorId: "fn", tier: TIER_FUNCTION, sortKey: "b" },
    ];
    const deg = effectiveFunctionDegrees(functions, [
      { source: "ep", target: "fn" },
    ]);
    expect(deg.get("ep")).toBe(1 + ENTRYPOINT_DEGREE_BONUS);
    expect(deg.get("fn")).toBe(1);
  });
});

describe("computeFunctionDegrees", () => {
  it("counts incident edges per function", () => {
    const ids = new Set(["f1", "f2", "f3"]);
    const deg = computeFunctionDegrees(ids, [
      { source: "f1", target: "s1" },
      { source: "f1", target: "f2" },
      { source: "f2", target: "f3" },
    ]);
    expect(deg.get("f1")).toBe(2);
    expect(deg.get("f2")).toBe(2);
    expect(deg.get("f3")).toBe(1);
  });
});

describe("gridPositionsForMainCells", () => {
  it("places public above state and internal below", () => {
    const positions = gridPositionsForMainCells([
      { anchorId: "s1", tier: TIER_STATE, sortKey: "st" },
      { anchorId: "pub", tier: TIER_FUNCTION, sortKey: "a", visibility: "public" },
      { anchorId: "int", tier: TIER_FUNCTION, sortKey: "b", visibility: "internal" },
    ]);
    expect(positions.get("pub")!.y).toBeLessThan(positions.get("s1")!.y);
    expect(positions.get("int")!.y).toBeGreaterThan(positions.get("s1")!.y);
  });

  it("places events to the right of main content", () => {
    const positions = gridPositionsForMainCells([
      { anchorId: "s1", tier: TIER_STATE, sortKey: "st" },
      { anchorId: "e1", tier: TIER_EVENT, sortKey: "ev" },
    ]);
    expect(positions.get("e1")!.x).toBeGreaterThan(positions.get("s1")!.x);
  });

  it("places all state cells on one horizontal row", () => {
    const positions = gridPositionsForMainCells([
      { anchorId: "s1", tier: TIER_STATE, sortKey: "a" },
      { anchorId: "s2", tier: TIER_STATE, sortKey: "b" },
      { anchorId: "s3", tier: TIER_STATE, sortKey: "c" },
    ]);
    const y = positions.get("s1")!.y;
    expect(positions.get("s2")!.y).toBe(y);
    expect(positions.get("s3")!.y).toBe(y);
  });

  it("places entrypoint closer to state than low-degree internal in a split band", () => {
    const functions = Array.from({ length: MAX_FUNCTIONS_PER_ROW + 2 }, (_, i) => ({
      anchorId: `f${i}`,
      tier: TIER_FUNCTION,
      sortKey: `z${i}`,
      visibility: "internal" as const,
      isEntrypoint: i === 7,
    }));
    const edges = functions
      .filter((f) => f.anchorId !== "f7")
      .map((f) => ({ source: "f7", target: f.anchorId }));
    const positions = gridPositionsForMainCells(
      [{ anchorId: "s1", tier: TIER_STATE, sortKey: "st" }, ...functions],
      edges,
    );
    const stateY = positions.get("s1")!.y;
    expect(Math.abs(positions.get("f7")!.y - stateY)).toBeLessThan(
      Math.abs(positions.get("f3")!.y - stateY),
    );
  });
});

describe("gridPositionsForCells", () => {
  it("places tier rows without cell overlap", () => {
    const cells = [
      { anchorId: "s1", tier: TIER_STATE, sortKey: "a" },
      { anchorId: "s2", tier: TIER_STATE, sortKey: "b" },
      { anchorId: "m1", tier: TIER_MODIFIER, sortKey: "c" },
      { anchorId: "f1", tier: TIER_FUNCTION, sortKey: "d", visibility: "public" },
      { anchorId: "f2", tier: TIER_FUNCTION, sortKey: "e", visibility: "internal" },
      { anchorId: "e1", tier: TIER_EVENT, sortKey: "g" },
    ];
    const positions = gridPositionsForCells(cells);
    const radius = Math.min(CELL_WIDTH, CELL_HEIGHT) * 0.45;
    expect(countCircularOverlaps(positions, radius)).toBe(0);
  });

  it("is stable for the same input", () => {
    const cells = [
      { anchorId: "f2", tier: TIER_FUNCTION, sortKey: "b", visibility: "public" },
      { anchorId: "f1", tier: TIER_FUNCTION, sortKey: "a", visibility: "internal" },
      { anchorId: "s1", tier: TIER_STATE, sortKey: "s" },
    ];
    const a = gridPositionsForCells(cells);
    const b = gridPositionsForCells(cells);
    expect(a.get("f1")).toEqual(b.get("f1"));
    expect(a.get("s1")).toEqual(b.get("s1"));
  });

  it("places modifiers in the top-left corner away from main bands", () => {
    const positions = gridPositionsForCells([
      { anchorId: "m1", tier: TIER_MODIFIER, sortKey: "modA" },
      { anchorId: "m2", tier: TIER_MODIFIER, sortKey: "modB" },
      { anchorId: "s1", tier: TIER_STATE, sortKey: "st" },
      { anchorId: "f1", tier: TIER_FUNCTION, sortKey: "fn", visibility: "public" },
    ]);
    expect(positions.get("m1")!.x).toBeLessThan(positions.get("s1")!.x);
    expect(positions.get("m2")!.x).toBeLessThan(positions.get("s1")!.x);
    expect(positions.get("m1")!.y).toBeLessThanOrEqual(positions.get("s1")!.y);
    expect(positions.get("m2")!.y).toBeGreaterThan(positions.get("m1")!.y);
  });

  it("puts high-degree functions closer to the state line when split", () => {
    const functions = Array.from({ length: MAX_FUNCTIONS_PER_ROW + 2 }, (_, i) => ({
      anchorId: `f${i}`,
      tier: TIER_FUNCTION,
      sortKey: `z${i}`,
      visibility: "internal" as const,
    }));
    const edges = functions
      .filter((f) => f.anchorId !== "f7")
      .map((f) => ({ source: "f7", target: f.anchorId }));
    const positions = gridPositionsForCells(
      [{ anchorId: "s1", tier: TIER_STATE, sortKey: "st" }, ...functions],
      edges,
    );
    const stateY = positions.get("s1")!.y;
    const hubY = positions.get("f7")!.y;
    const farRowY = positions.get("f3")!.y;
    expect(Math.abs(hubY - stateY)).toBeLessThan(Math.abs(farRowY - stateY));
  });
});

describe("gridPositionsForOuterCompounds", () => {
  it("separates multiple top-level compounds", () => {
    const positions = gridPositionsForOuterCompounds([
      { id: "type:A", width: 200, height: 180, sortKey: "A" },
      { id: "type:B", width: 240, height: 200, sortKey: "B" },
      { id: "type:C", width: 180, height: 160, sortKey: "C" },
    ]);
    const a = positions.get("type:A")!;
    const b = positions.get("type:B")!;
    const c = positions.get("type:C")!;
    expect(a.x).not.toBeCloseTo(b.x, 0);
    expect(b.x).not.toBeCloseTo(c.x, 0);
    expect(countCircularOverlaps(positions, 100)).toBe(0);
  });
});
