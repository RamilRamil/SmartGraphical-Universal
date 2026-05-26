import { describe, expect, it } from "vitest";

import {
  CELL_HEIGHT,
  CELL_WIDTH,
  countCircularOverlaps,
  gridPositionsForCells,
  gridPositionsForOuterCompounds,
  pickInteriorLayoutRootIds,
  TIER_EVENT,
  TIER_FUNCTION,
  TIER_MODIFIER,
  TIER_STATE,
  tierForGroup,
} from "./intraCompoundLayout";

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

describe("gridPositionsForCells", () => {
  it("places tier rows without cell overlap", () => {
    const cells = [
      { anchorId: "s1", tier: TIER_STATE, sortKey: "a" },
      { anchorId: "s2", tier: TIER_STATE, sortKey: "b" },
      { anchorId: "m1", tier: TIER_MODIFIER, sortKey: "c" },
      { anchorId: "f1", tier: TIER_FUNCTION, sortKey: "d" },
      { anchorId: "f2", tier: TIER_FUNCTION, sortKey: "e" },
      { anchorId: "f3", tier: TIER_FUNCTION, sortKey: "f" },
      { anchorId: "e1", tier: TIER_EVENT, sortKey: "g" },
    ];
    const positions = gridPositionsForCells(cells);
    const radius = Math.min(CELL_WIDTH, CELL_HEIGHT) * 0.45;
    expect(countCircularOverlaps(positions, radius)).toBe(0);
  });

  it("is stable for the same input", () => {
    const cells = [
      { anchorId: "f2", tier: TIER_FUNCTION, sortKey: "b" },
      { anchorId: "f1", tier: TIER_FUNCTION, sortKey: "a" },
    ];
    const a = gridPositionsForCells(cells);
    const b = gridPositionsForCells(cells);
    expect(a.get("f1")).toEqual(b.get("f1"));
    expect(a.get("f2")).toEqual(b.get("f2"));
  });

  it("orders tiers top-to-bottom: state, then functions, then events", () => {
    const positions = gridPositionsForCells([
      { anchorId: "e1", tier: TIER_EVENT, sortKey: "z" },
      { anchorId: "s1", tier: TIER_STATE, sortKey: "a" },
      { anchorId: "f1", tier: TIER_FUNCTION, sortKey: "m" },
    ]);
    const sy = positions.get("s1")!.y;
    const fy = positions.get("f1")!.y;
    const ey = positions.get("e1")!.y;
    expect(sy).toBeLessThan(fy);
    expect(fy).toBeLessThan(ey);
  });

  it("separates tier bands by at least REGION_GAP", () => {
    const positions = gridPositionsForCells([
      { anchorId: "s1", tier: TIER_STATE, sortKey: "a" },
      { anchorId: "f1", tier: TIER_FUNCTION, sortKey: "b" },
    ]);
    const gap = positions.get("f1")!.y - positions.get("s1")!.y;
    expect(gap).toBeGreaterThan(CELL_HEIGHT);
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
