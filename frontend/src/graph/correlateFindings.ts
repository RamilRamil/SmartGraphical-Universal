import type { Finding, GraphNode } from "../api/types";

/**
 * Pure correlation between heuristic findings and interactive-graph nodes
 * (feature 012). Matches a finding's evidence (`type_name` / `function_name`)
 * to graph nodes by their existing `type_name` / `label`, so it never
 * reconstructs the serializer's id scheme (`type:` / `function:` / `tile:`) and
 * works identically across Solidity, C and Rust/Stellar.
 *
 * See specs/012-findings-graph-overlay/contracts/correlation-module.md (R1-R7).
 */

export type Confidence = "high" | "medium" | "low";

export type NodeFindingSummary = {
  nodeId: string;
  count: number;
  maxConfidence: Confidence;
  /** Indices into the findings array passed to correlateFindings. */
  findingRefs: number[];
};

export type FindingsCorrelation = {
  byNodeId: ReadonlyMap<string, NodeFindingSummary>;
  /** Node id(s) a finding maps to; [] means unmapped. */
  nodeIdsForFindingIndex: (index: number) => string[];
  /** Indices of findings that mapped to no node. */
  unmappedIndices: number[];
};

const CONFIDENCE_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };

function rankOf(confidence: string): number {
  return CONFIDENCE_RANK[confidence] ?? 0; // unknown -> lowest (R5)
}

function confidenceFromRank(rank: number): Confidence {
  if (rank >= 3) return "high";
  if (rank === 2) return "medium";
  return "low";
}

const CONTAINER_GROUPS: ReadonlySet<GraphNode["group"]> = new Set(["type", "tile"]);

/** First evidence carrying a usable target, falling back across evidences. */
function primaryEvidence(finding: Finding) {
  const evidences = finding.evidences ?? [];
  for (const ev of evidences) {
    if (ev && ((ev.type_name || "").trim() || (ev.function_name || "").trim())) {
      return ev;
    }
  }
  return evidences[0] ?? null;
}

function matchNodeIds(finding: Finding, nodes: readonly GraphNode[]): string[] {
  const ev = primaryEvidence(finding);
  if (!ev) return [];
  const typeName = (ev.type_name || "").trim();
  const fnName = (ev.function_name || "").trim();
  if (!typeName) return []; // R3: no resolvable target

  const ids: string[] = [];
  if (fnName) {
    // R1: function match
    for (const n of nodes) {
      if (n.group === "function" && n.type_name === typeName && n.label === fnName) {
        ids.push(n.id);
      }
    }
    return ids;
  }
  // R2: type/container match
  for (const n of nodes) {
    if (CONTAINER_GROUPS.has(n.group) && n.type_name === typeName) {
      ids.push(n.id);
    }
  }
  return ids;
}

export function correlateFindings(
  findings: readonly Finding[],
  nodes: readonly GraphNode[],
): FindingsCorrelation {
  const byNodeId = new Map<string, NodeFindingSummary>();
  const perFinding: string[][] = [];
  const unmappedIndices: number[] = [];

  findings.forEach((finding, index) => {
    const nodeIds = matchNodeIds(finding, nodes);
    perFinding[index] = nodeIds;
    if (nodeIds.length === 0) {
      unmappedIndices.push(index); // R3
      return;
    }
    const rank = rankOf(finding.confidence);
    for (const nodeId of nodeIds) {
      const existing = byNodeId.get(nodeId);
      if (existing) {
        existing.count += 1; // R5/R6
        existing.findingRefs.push(index);
        existing.maxConfidence = confidenceFromRank(
          Math.max(rankOf(existing.maxConfidence), rank),
        );
      } else {
        byNodeId.set(nodeId, {
          nodeId,
          count: 1,
          maxConfidence: confidenceFromRank(rank),
          findingRefs: [index],
        });
      }
    }
  });

  return {
    byNodeId,
    nodeIdsForFindingIndex: (index: number) => perFinding[index] ?? [],
    unmappedIndices,
  };
}
