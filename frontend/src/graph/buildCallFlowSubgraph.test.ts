import { describe, expect, it } from "vitest";

import type { GraphData, GraphEdge, GraphNode } from "../api/types";
import {
  buildCallFlowSubgraph,
  callFlowDisplayLabel,
  defaultCallFlowOptions,
  expandAllCallFlowOptions,
} from "./buildCallFlowSubgraph";

function fn(id: string, label: string, type = "C"): GraphNode {
  return {
    id,
    label,
    group: "function",
    type_name: type,
  };
}

function call(id: string, source: string, target: string, kind = "function_to_function"): GraphEdge {
  return { id, source, target, kind, label: "" };
}

function graph(nodes: GraphNode[], edges: GraphEdge[]): GraphData {
  return { nodes, edges };
}

describe("buildCallFlowSubgraph", () => {
  const nodes = [
    fn("f:a", "a"),
    fn("f:b", "b"),
    fn("f:c", "c"),
    fn("f:root", "root"),
    fn("f:d", "d"),
    fn("f:e", "e"),
  ];
  const edges = [
    call("e1", "f:a", "f:b"),
    call("e2", "f:b", "f:root"),
    call("e3", "f:root", "f:c"),
    call("e4", "f:c", "f:d"),
    call("e5", "f:d", "f:e"),
  ];

  it("collects both directions with depth 2", () => {
    const opts = defaultCallFlowOptions("f:root");
    const result = buildCallFlowSubgraph(graph(nodes, edges), opts);
    expect(result.nodes.map((n) => n.id).sort()).toEqual(
      ["f:a", "f:b", "f:c", "f:d", "f:root"].sort(),
    );
    expect(result.upstreamCount).toBe(2);
    expect(result.downstreamCount).toBe(2);
    expect(result.edges).toHaveLength(4);
    expect(result.truncated).toBe(false);
  });

  it("limits downstream to depth 1", () => {
    const opts = { ...defaultCallFlowOptions("f:root"), direction: "downstream" as const, depth: 1 };
    const result = buildCallFlowSubgraph(graph(nodes, edges), opts);
    expect(result.nodes.map((n) => n.id).sort()).toEqual(["f:c", "f:root"].sort());
  });

  it("expand all reaches end of chain when small", () => {
    const opts = expandAllCallFlowOptions("f:root");
    const result = buildCallFlowSubgraph(graph(nodes, edges), opts);
    expect(result.nodes).toHaveLength(6);
    expect(result.edges).toHaveLength(5);
  });

  it("marks truncated when node cap exceeded", () => {
    const many: GraphNode[] = [fn("f:root", "root")];
    const manyEdges: GraphEdge[] = [];
    for (let i = 0; i < 100; i += 1) {
      const id = `f:n${i}`;
      many.push(fn(id, `n${i}`));
      manyEdges.push(call(`e${i}`, "f:root", id));
    }
    const opts = {
      ...expandAllCallFlowOptions("f:root"),
      maxNodes: 10,
    };
    const result = buildCallFlowSubgraph(graph(many, manyEdges), opts);
    expect(result.truncated).toBe(true);
    expect(result.nodes.length).toBeLessThanOrEqual(10);
  });

  it("includes cross_contract_call when in edge kinds", () => {
    const g = graph(
      [fn("f:a", "a", "A"), fn("f:b", "b", "B")],
      [call("x", "f:a", "f:b", "cross_contract_call")],
    );
    const result = buildCallFlowSubgraph(g, defaultCallFlowOptions("f:a"));
    expect(result.edges).toHaveLength(1);
    expect(result.nodes).toHaveLength(2);
  });

  it("returns root only when no call edges in direction", () => {
    const g = graph([fn("f:x", "x")], []);
    const result = buildCallFlowSubgraph(
      g,
      { ...defaultCallFlowOptions("f:x"), direction: "downstream" },
    );
    expect(result.nodes).toHaveLength(1);
    expect(result.edges).toHaveLength(0);
    expect(result.stubCount).toBe(0);
  });

  it("attaches external stub for cross_contract to non-function target", () => {
    const ext: GraphNode = {
      id: "external:IERC20.transfer",
      label: "transfer",
      group: "external",
    };
    const g = graph(
      [fn("f:deposit", "deposit", "Vault"), ext],
      [
        {
          id: "e-ext",
          source: "f:deposit",
          target: ext.id,
          kind: "cross_contract_call",
          label: "token.transfer",
        },
      ],
    );
    const result = buildCallFlowSubgraph(g, defaultCallFlowOptions("f:deposit"));
    expect(result.functionCount).toBe(1);
    expect(result.stubCount).toBe(1);
    expect(result.nodes.map((n) => n.id).sort()).toEqual(["f:deposit", ext.id].sort());
    expect(result.edges).toHaveLength(1);
    expect(result.nodes.find((n) => n.id === ext.id)?.callFlowRole).toBe("stub");
    expect(callFlowDisplayLabel(ext, { edgeLabel: "token.transfer" })).toBe(
      "token.transfer",
    );
  });

  it("does not expand BFS through stub nodes", () => {
    const ext: GraphNode = {
      id: "external:x",
      label: "x",
      group: "external",
    };
    const g = graph(
      [fn("f:a", "a"), fn("f:c", "c"), ext],
      [
        {
          id: "e1",
          source: "f:a",
          target: ext.id,
          kind: "cross_contract_call",
          label: "",
        },
        call("e2", ext.id, "f:c"),
      ],
    );
    const result = buildCallFlowSubgraph(g, defaultCallFlowOptions("f:a"));
    expect(result.nodes.map((n) => n.id)).toContain("f:a");
    expect(result.nodes.map((n) => n.id)).toContain(ext.id);
    expect(result.nodes.map((n) => n.id)).not.toContain("f:c");
    expect(result.stubCount).toBe(1);
  });

  it("shows stub leaf when callee is in subgraph", () => {
    const ext: GraphNode = {
      id: "external:x",
      label: "x",
      group: "external",
    };
    const g = graph(
      [fn("f:a", "a"), fn("f:b", "b"), ext],
      [
        call("e1", "f:a", "f:b"),
        {
          id: "e2",
          source: "f:b",
          target: ext.id,
          kind: "cross_contract_call",
          label: "",
        },
      ],
    );
    const result = buildCallFlowSubgraph(
      g,
      { ...defaultCallFlowOptions("f:a"), direction: "downstream", depth: 1 },
    );
    expect(result.nodes.map((n) => n.id).sort()).toEqual(["external:x", "f:a", "f:b"].sort());
    expect(result.stubCount).toBe(1);
  });
});
