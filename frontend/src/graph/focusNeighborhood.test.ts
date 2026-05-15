import { describe, expect, it } from "vitest";

import type { GraphData, GraphEdge, GraphNode } from "../api/types";

import { buildFocusNodeSet } from "./focusNeighborhood";

function g(nodes: GraphNode[], edges: GraphEdge[]): GraphData {
  return { nodes, edges };
}

describe("buildFocusNodeSet", () => {
  it("returns null when focus disabled or no selection", () => {
    const data = g(
      [{ id: "type:A", label: "A", group: "type" }],
      [],
    );
    expect(buildFocusNodeSet(data, "type:A", false)).toBeNull();
    expect(buildFocusNodeSet(data, null, true)).toBeNull();
  });

  it("returns null for non-type tile roots", () => {
    const data = g(
      [
        { id: "type:A", label: "A", group: "type" },
        { id: "function:A.f", label: "f", group: "function", parent: "type:A" },
      ],
      [],
    );
    expect(buildFocusNodeSet(data, "function:A.f", true)).toBeNull();
  });

  it("expands two hops so shared hub pulls in peer contract (variant B)", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:B", label: "B", group: "type" },
      { id: "type:I", label: "I", group: "type", solidity_kind: "interface" },
    ];
    const edges: GraphEdge[] = [
      { id: "e1", source: "type:A", target: "type:I", kind: "import_dependency", label: "" },
      { id: "e2", source: "type:B", target: "type:I", kind: "import_dependency", label: "" },
    ];
    const data = g(nodes, edges);
    const set = buildFocusNodeSet(data, "type:A", true);
    expect(set).not.toBeNull();
    expect(set!.has("type:A")).toBe(true);
    expect(set!.has("type:I")).toBe(true);
    expect(set!.has("type:B")).toBe(true);
  });

  it("includes only one hop when no second layer", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:I", label: "I", group: "type" },
    ];
    const edges: GraphEdge[] = [
      { id: "e1", source: "type:A", target: "type:I", kind: "function_to_function", label: "" },
    ];
    const data = g(nodes, edges);
    const set = buildFocusNodeSet(data, "type:A", true);
    expect(set!.size).toBe(2);
  });
});
