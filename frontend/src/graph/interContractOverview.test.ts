import { describe, expect, it } from "vitest";

import type { GraphData, GraphEdge, GraphNode } from "../api/types";

import {
  filterFullGraphEdges,
  isTypeCompoundInterContractEdge,
  toInterContractOverviewGraph,
} from "./interContractOverview";

function minimalGraph(nodes: GraphNode[], edges: GraphEdge[]): GraphData {
  return { nodes, edges };
}

describe("filterFullGraphEdges", () => {
  it("hides cross_type_call when toggle is off", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:B", label: "B", group: "type" },
    ];
    const edges: GraphEdge[] = [
      {
        id: "xt",
        source: "type:A",
        target: "type:B",
        kind: "cross_type_call",
        label: "extends B",
      },
      {
        id: "ff",
        source: "function:A.f",
        target: "function:A.g",
        kind: "function_to_function",
        label: "",
      },
    ];
    const g = minimalGraph(nodes, edges);
    const out = filterFullGraphEdges(g, false);
    expect(out.edges.map((e) => e.kind)).toEqual(["function_to_function"]);
  });

  it("hides type-to-type extends even when toggle is on", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:B", label: "B", group: "type" },
    ];
    const edges: GraphEdge[] = [
      {
        id: "xt",
        source: "type:A",
        target: "type:B",
        kind: "cross_type_call",
        label: "extends B",
      },
      {
        id: "bi",
        source: "type:A",
        target: "type:B",
        kind: "bundle_import",
        label: "solidity_import",
      },
    ];
    const g = minimalGraph(nodes, edges);
    const byId = new Map(nodes.map((n) => [n.id, n]));
    expect(isTypeCompoundInterContractEdge(edges[0]!, byId)).toBe(true);
    const out = filterFullGraphEdges(g, true);
    expect(out.edges.map((e) => e.kind)).toEqual(["bundle_import"]);
  });

  it("shows function-level cross_type_call when toggle is on", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      {
        id: "function:A.f",
        label: "f",
        group: "function",
        parent: "type:A",
      },
      { id: "type:B", label: "B", group: "type" },
      {
        id: "function:B.g",
        label: "g",
        group: "function",
        parent: "type:B",
      },
    ];
    const edges: GraphEdge[] = [
      {
        id: "xt",
        source: "function:A.f",
        target: "function:B.g",
        kind: "cross_type_call",
        label: "g()",
      },
    ];
    const out = filterFullGraphEdges(minimalGraph(nodes, edges), true);
    expect(out.edges.map((e) => e.kind)).toEqual(["cross_type_call"]);
  });
});

describe("toInterContractOverviewGraph", () => {
  it("keeps only type, tile, external, and external_import nodes", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "function:A.f", label: "f", group: "function", parent: "type:A" },
      { id: "external:X", label: "X", group: "external" },
    ];
    const g = minimalGraph(nodes, []);
    const ov = toInterContractOverviewGraph(g);
    expect(ov.nodes.map((n) => n.id).sort()).toEqual(["external:X", "type:A"]);
  });

  it("drops file tiles and clears parents when contract types exist (Solidity-style)", () => {
    const nodes: GraphNode[] = [
      { id: "tile:file", label: "C.sol", group: "tile" },
      { id: "type:A", label: "A", group: "type", parent: "tile:file" },
      { id: "type:B", label: "B", group: "type", parent: "tile:file" },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, []));
    expect(ov.nodes.map((n) => n.id).sort()).toEqual(["type:A", "type:B"]);
    expect(ov.nodes.every((n) => n.parent === undefined)).toBe(true);
  });

  it("drops edges that resolve to the same compound", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      {
        id: "function:A.f",
        label: "f",
        group: "function",
        parent: "type:A",
      },
      {
        id: "function:A.g",
        label: "g",
        group: "function",
        parent: "type:A",
      },
    ];
    const edges: GraphEdge[] = [
      {
        id: "e1",
        source: "function:A.f",
        target: "function:A.g",
        kind: "function_to_function",
        label: "",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.nodes).toHaveLength(1);
    expect(ov.edges).toHaveLength(0);
  });

  it("keeps edges between two different compounds", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:B", label: "B", group: "type" },
      {
        id: "function:A.f",
        label: "f",
        group: "function",
        parent: "type:A",
      },
      {
        id: "function:B.g",
        label: "g",
        group: "function",
        parent: "type:B",
      },
    ];
    const edges: GraphEdge[] = [
      {
        id: "e1",
        source: "function:A.f",
        target: "function:B.g",
        kind: "function_to_function",
        label: "",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.edges).toHaveLength(1);
    expect(ov.edges[0]?.source).toBe("type:A");
    expect(ov.edges[0]?.target).toBe("type:B");
    expect(ov.edges[0]?.kind).toBe("function_to_function");
  });

  it("maps function endpoint to external node", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      {
        id: "function:A.f",
        label: "f",
        group: "function",
        parent: "type:A",
      },
      { id: "external:token", label: "token", group: "external" },
    ];
    const edges: GraphEdge[] = [
      {
        id: "e1",
        source: "function:A.f",
        target: "external:token",
        kind: "cross_contract_call",
        label: "",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.edges).toHaveLength(1);
    expect(ov.edges[0]?.source).toBe("type:A");
    expect(ov.edges[0]?.target).toBe("external:token");
  });

  it("deduplicates parallel edges with same source, target, and kind", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:B", label: "B", group: "type" },
      {
        id: "function:A.f1",
        label: "f1",
        group: "function",
        parent: "type:A",
      },
      {
        id: "function:A.f2",
        label: "f2",
        group: "function",
        parent: "type:A",
      },
      {
        id: "function:B.g",
        label: "g",
        group: "function",
        parent: "type:B",
      },
    ];
    const edges: GraphEdge[] = [
      {
        id: "a",
        source: "function:A.f1",
        target: "function:B.g",
        kind: "function_to_function",
        label: "",
      },
      {
        id: "b",
        source: "function:A.f2",
        target: "function:B.g",
        kind: "function_to_function",
        label: "",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.edges).toHaveLength(1);
  });

  it("keeps two edges between the same compounds when kinds differ", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:B", label: "B", group: "type" },
      {
        id: "function:A.f",
        label: "f",
        group: "function",
        parent: "type:A",
      },
      {
        id: "function:B.g",
        label: "g",
        group: "function",
        parent: "type:B",
      },
    ];
    const edges: GraphEdge[] = [
      {
        id: "a",
        source: "function:A.f",
        target: "function:B.g",
        kind: "function_to_function",
        label: "",
      },
      {
        id: "b",
        source: "function:A.f",
        target: "function:B.g",
        kind: "import_dependency",
        label: "",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.edges).toHaveLength(2);
    const kinds = ov.edges.map((e) => e.kind).sort();
    expect(kinds).toEqual(["function_to_function", "import_dependency"]);
  });

  it("walks through modifier_ring parent chain to type", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      {
        id: "function:A.f",
        label: "f",
        group: "function",
        parent: "type:A",
      },
      {
        id: "type:B",
        label: "B",
        group: "type",
      },
      {
        id: "function:B.g",
        label: "g",
        group: "function",
        parent: "type:B",
      },
      {
        id: "ring",
        label: "",
        group: "modifier_ring",
        parent: "function:A.f",
      },
    ];
    const edges: GraphEdge[] = [
      {
        id: "e1",
        source: "ring",
        target: "function:B.g",
        kind: "function_to_function",
        label: "",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.edges).toHaveLength(1);
    expect(ov.edges[0]?.source).toBe("type:A");
    expect(ov.edges[0]?.target).toBe("type:B");
  });

  it("updates exploration_hints counts when hints were present", () => {
    const nodes: GraphNode[] = [
      { id: "type:A", label: "A", group: "type" },
      { id: "type:B", label: "B", group: "type" },
    ];
    const g: GraphData = {
      nodes,
      edges: [],
      exploration_hints: {
        call_edges_are_heuristic: true,
        call_edge_count: 99,
        node_count: 999,
        edge_count: 888,
      },
    };
    const ov = toInterContractOverviewGraph(g);
    expect(ov.exploration_hints?.node_count).toBe(2);
    expect(ov.exploration_hints?.edge_count).toBe(0);
    expect(ov.exploration_hints?.call_edges_are_heuristic).toBe(true);
    expect(ov.exploration_hints?.call_edge_count).toBe(99);
  });

  it("adds minimal exploration_hints when graph had none", () => {
    const nodes: GraphNode[] = [{ id: "type:A", label: "A", group: "type" }];
    const g = minimalGraph(nodes, []);
    const ov = toInterContractOverviewGraph(g);
    expect(ov.exploration_hints).toMatchObject({
      node_count: 1,
      edge_count: 0,
      call_edge_count: 0,
      call_edges_are_heuristic: false,
    });
  });

  it("uses tile as compound root for C-style graphs", () => {
    const nodes: GraphNode[] = [
      { id: "tile:tu1", label: "tu1", group: "tile" },
      { id: "tile:tu2", label: "tu2", group: "tile" },
      {
        id: "function:tu1.main",
        label: "main",
        group: "function",
        parent: "tile:tu1",
      },
      {
        id: "function:tu2.aux",
        label: "aux",
        group: "function",
        parent: "tile:tu2",
      },
    ];
    const edges: GraphEdge[] = [
      {
        id: "e1",
        source: "function:tu1.main",
        target: "function:tu2.aux",
        kind: "cross_type_call",
        label: "",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.nodes.map((n) => n.id).sort()).toEqual(["tile:tu1", "tile:tu2"]);
    expect(ov.edges[0]?.source).toBe("tile:tu1");
    expect(ov.edges[0]?.target).toBe("tile:tu2");
  });

  it("drops bundle_import when cross_type_call already links the pair", () => {
    const nodes: GraphNode[] = [
      { id: "type:Child", label: "Child", group: "type" },
      { id: "type:Base", label: "Base", group: "type" },
    ];
    const edges: GraphEdge[] = [
      {
        id: "bi",
        source: "type:Child",
        target: "type:Base",
        kind: "bundle_import",
        label: "solidity_import",
      },
      {
        id: "ext",
        source: "type:Child",
        target: "type:Base",
        kind: "cross_type_call",
        label: "extends Base",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.edges.map((e) => e.kind)).toEqual(["cross_type_call"]);
  });

  it("keeps bundle_import when no semantic cross-type edge exists", () => {
    const nodes: GraphNode[] = [
      { id: "type:User", label: "User", group: "type" },
      { id: "type:Lib", label: "Lib", group: "type" },
    ];
    const edges: GraphEdge[] = [
      {
        id: "bi",
        source: "type:User",
        target: "type:Lib",
        kind: "bundle_import",
        label: "solidity_import",
      },
    ];
    const ov = toInterContractOverviewGraph(minimalGraph(nodes, edges));
    expect(ov.edges.map((e) => e.kind)).toEqual(["bundle_import"]);
  });
});
