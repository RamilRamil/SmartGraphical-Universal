import { describe, expect, it } from "vitest";

import type { GraphDiffNode, GraphDiffResponse } from "../api/types";
import {
  changedFields,
  describeEdge,
  graphDiffTotalChanges,
  groupNodesByGroup,
  isGraphDiffEmpty,
} from "./graphDiffSummary";

function node(id: string, group = "function"): GraphDiffNode {
  return { id, group, label: id, kind: "" };
}

function diff(partial: Partial<GraphDiffResponse>): GraphDiffResponse {
  return {
    scan_a_id: 1,
    scan_b_id: 2,
    artifact_id: 1,
    graph_available: true,
    added_nodes: [],
    removed_nodes: [],
    changed_nodes: [],
    added_edges: [],
    removed_edges: [],
    added_node_count: 0,
    removed_node_count: 0,
    changed_node_count: 0,
    added_edge_count: 0,
    removed_edge_count: 0,
    unchanged_node_count: 0,
    ...partial,
  };
}

describe("graphDiffSummary", () => {
  it("totals all change buckets", () => {
    const d = diff({
      added_node_count: 2,
      removed_node_count: 1,
      changed_node_count: 3,
      added_edge_count: 4,
      removed_edge_count: 5,
    });
    expect(graphDiffTotalChanges(d)).toBe(15);
    expect(isGraphDiffEmpty(d)).toBe(false);
  });

  it("detects an empty (identical) diff", () => {
    expect(isGraphDiffEmpty(diff({ unchanged_node_count: 7 }))).toBe(true);
  });

  it("groups nodes by group with sorted keys", () => {
    const grouped = groupNodesByGroup([
      node("state:C.x", "state"),
      node("function:C.f", "function"),
      node("function:C.g", "function"),
    ]);
    expect(grouped.map((g) => g.group)).toEqual(["function", "state"]);
    expect(grouped[0]?.nodes).toHaveLength(2);
  });

  it("describes an edge with and without kind", () => {
    expect(
      describeEdge({ source: "a", target: "b", kind: "function_to_function", label: "" }),
    ).toBe("a → b (function_to_function)");
    expect(describeEdge({ source: "a", target: "b", kind: "", label: "" })).toBe("a → b");
  });

  it("reports which fields changed", () => {
    expect(
      changedFields({
        id: "function:C.f",
        before: { group: "function", label: "foo", kind: "x" },
        after: { group: "function", label: "bar", kind: "x" },
      }),
    ).toEqual(["label"]);
  });
});
