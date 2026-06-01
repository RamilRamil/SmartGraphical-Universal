import { describe, expect, it } from "vitest";

import type { Evidence, Finding, GraphNode } from "../api/types";
import { correlateFindings } from "./correlateFindings";

function ev(partial: Partial<Evidence>): Evidence {
  return {
    kind: "",
    summary: "",
    type_name: "",
    function_name: "",
    statement: "",
    source_statement: "",
    confidence_reason: "",
    ...partial,
  };
}

function finding(confidence: string, evidence: Partial<Evidence>): Finding {
  return {
    task_id: "1",
    legacy_code: 1,
    rule_id: "rule",
    title: "title",
    category: "cat",
    portability: "portable",
    confidence,
    message: "msg",
    remediation_hint: "hint",
    evidences: [ev(evidence)],
  };
}

function fnNode(id: string, typeName: string, label: string): GraphNode {
  return { id, label, group: "function", type_name: typeName };
}

function containerNode(group: "type" | "tile", id: string, name: string): GraphNode {
  return { id, label: name, group, type_name: name };
}

describe("correlateFindings", () => {
  it("maps a Solidity function finding to its function node (R1)", () => {
    const nodes = [
      containerNode("type", "type:Auction", "Auction"),
      fnNode("function:Auction.bid", "Auction", "bid"),
    ];
    const c = correlateFindings(
      [finding("high", { type_name: "Auction", function_name: "bid" })],
      nodes,
    );
    expect(c.nodeIdsForFindingIndex(0)).toEqual(["function:Auction.bid"]);
    expect(c.byNodeId.get("function:Auction.bid")).toMatchObject({
      count: 1,
      maxConfidence: "high",
    });
    expect(c.unmappedIndices).toEqual([]);
  });

  it("maps a C type-only finding to the tile container node (R2)", () => {
    const nodes = [
      containerNode("tile", "tile:Tu", "Tu"),
      fnNode("function:tests.Tu.use", "Tu", "use"),
    ];
    const c = correlateFindings([finding("medium", { type_name: "Tu" })], nodes);
    expect(c.nodeIdsForFindingIndex(0)).toEqual(["tile:Tu"]);
    expect(c.byNodeId.get("tile:Tu")?.maxConfidence).toBe("medium");
  });

  it("maps a Rust function finding by type_name + label", () => {
    const nodes = [fnNode("function:Contract.transfer", "Contract", "transfer")];
    const c = correlateFindings(
      [finding("low", { type_name: "Contract", function_name: "transfer" })],
      nodes,
    );
    expect(c.nodeIdsForFindingIndex(0)).toEqual(["function:Contract.transfer"]);
  });

  it("aggregates mixed confidence on one node: count and highest (R5)", () => {
    const nodes = [fnNode("function:A.f", "A", "f")];
    const c = correlateFindings(
      [
        finding("low", { type_name: "A", function_name: "f" }),
        finding("high", { type_name: "A", function_name: "f" }),
        finding("medium", { type_name: "A", function_name: "f" }),
      ],
      nodes,
    );
    const summary = c.byNodeId.get("function:A.f");
    expect(summary?.count).toBe(3);
    expect(summary?.maxConfidence).toBe("high");
    expect(summary?.findingRefs).toEqual([0, 1, 2]);
  });

  it("counts a finding on every matching node (R6 multi-match)", () => {
    const nodes = [
      containerNode("tile", "tile:X", "X"),
      containerNode("type", "type:X", "X"),
    ];
    const c = correlateFindings([finding("medium", { type_name: "X" })], nodes);
    expect(new Set(c.nodeIdsForFindingIndex(0))).toEqual(
      new Set(["tile:X", "type:X"]),
    );
    expect(c.byNodeId.get("tile:X")?.count).toBe(1);
    expect(c.byNodeId.get("type:X")?.count).toBe(1);
  });

  it("treats unknown confidence as lowest", () => {
    const nodes = [fnNode("function:A.f", "A", "f")];
    const c = correlateFindings(
      [finding("bogus", { type_name: "A", function_name: "f" })],
      nodes,
    );
    expect(c.byNodeId.get("function:A.f")?.maxConfidence).toBe("low");
  });

  it("collects unmapped findings, dropping none (R3)", () => {
    const nodes = [fnNode("function:A.f", "A", "f")];
    const c = correlateFindings(
      [
        finding("high", {}), // no type/function
        finding("high", { type_name: "A", function_name: "ghost" }), // no such fn
      ],
      nodes,
    );
    expect(c.unmappedIndices).toEqual([0, 1]);
    expect(c.byNodeId.size).toBe(0);
  });
});
