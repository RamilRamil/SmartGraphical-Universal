import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";

import type { GraphData, GraphNode } from "../api/types";
import {
  buildCallFlowSubgraph,
  callFlowDisplayLabel,
  CALL_FLOW_FULL_MAX_NODES,
  CALL_FLOW_LIMITED_MAX_NODES,
  defaultCallFlowOptions,
  expandAllCallFlowOptions,
  type CallFlowDepthMode,
  type CallFlowDirection,
  type CallFlowGraphNode,
  type CallFlowOptions,
} from "../graph/buildCallFlowSubgraph";
import {
  defaultCallFlowSessionPrefs,
  loadCallFlowSessionPrefs,
  saveCallFlowSessionPrefs,
} from "../graph/callFlowSessionPrefs";

type CallFlowModalProps = {
  graph: GraphData;
  root: GraphNode;
  /** Called when modal closes; optional node id to select on the main graph. */
  onClose: (mainGraphNodeId?: string) => void;
};

function edgeColor(kind: string): string {
  switch (kind) {
    case "function_to_function":
      return "#34d399";
    case "cross_type_call":
      return "#a78bfa";
    case "cross_contract_call":
      return "#6366f1";
    default:
      return "#6b7280";
  }
}

function stubEdgeLabel(
  nodeId: string,
  edges: ReturnType<typeof buildCallFlowSubgraph>["edges"],
): string | undefined {
  for (const edge of edges) {
    if (edge.target === nodeId && edge.label?.trim()) {
      return edge.label.trim();
    }
  }
  return undefined;
}

function buildElements(
  nodes: CallFlowGraphNode[],
  edges: ReturnType<typeof buildCallFlowSubgraph>["edges"],
  rootId: string,
): ElementDefinition[] {
  const elements: ElementDefinition[] = nodes.map((node) => ({
    data: {
      id: node.id,
      label: callFlowDisplayLabel(node, {
        edgeLabel: node.callFlowRole === "stub" ? stubEdgeLabel(node.id, edges) : undefined,
      }),
      isRoot: node.id === rootId,
      isStub: node.callFlowRole === "stub",
      mainGraphNodeId: node.id,
    },
  }));
  for (const edge of edges) {
    elements.push({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        kind: edge.kind,
      },
    });
  }
  return elements;
}

function callFlowPngFilename(root: GraphNode): string {
  const base = callFlowDisplayLabel(root).replace(/[^a-zA-Z0-9._-]+/g, "_");
  return `call-flow-${base || "function"}.png`;
}

export function CallFlowModal({ graph, root, onClose }: CallFlowModalProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const coreRef = useRef<Core | null>(null);
  const pendingMainNodeIdRef = useRef<string | null>(null);
  const initialPrefs = useMemo(() => loadCallFlowSessionPrefs(), []);

  const [direction, setDirection] = useState<CallFlowDirection>(initialPrefs.direction);
  const [depth, setDepth] = useState(initialPrefs.depth);
  const [depthMode, setDepthMode] = useState<CallFlowDepthMode>(initialPrefs.depthMode);
  const [showExternalCalls, setShowExternalCalls] = useState(initialPrefs.showExternalCalls);

  const options: CallFlowOptions = useMemo(() => {
    const kinds = new Set<string>([
      "function_to_function",
      "cross_type_call",
      ...(showExternalCalls ? ["cross_contract_call"] : []),
    ]);
    const base =
      depthMode === "full"
        ? expandAllCallFlowOptions(root.id)
        : defaultCallFlowOptions(root.id);
    return {
      ...base,
      direction,
      depthMode,
      depth,
      edgeKinds: kinds,
      maxNodes: depthMode === "full" ? CALL_FLOW_FULL_MAX_NODES : CALL_FLOW_LIMITED_MAX_NODES,
    };
  }, [root.id, direction, depth, depthMode, showExternalCalls]);

  const subgraph = useMemo(
    () => buildCallFlowSubgraph(graph, options),
    [graph, options],
  );

  const elements = useMemo(
    () => buildElements(subgraph.nodes, subgraph.edges, subgraph.rootId),
    [subgraph],
  );

  useEffect(() => {
    saveCallFlowSessionPrefs({
      direction,
      depth,
      depthMode,
      showExternalCalls,
    });
  }, [direction, depth, depthMode, showExternalCalls]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    if (coreRef.current) {
      coreRef.current.destroy();
      coreRef.current = null;
    }

    if (subgraph.nodes.length === 0) {
      return;
    }

    const core = cytoscape({
      container,
      elements,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": 11,
            "text-wrap": "wrap",
            "text-max-width": "140px",
            color: "#e6edf3",
            "background-color": "#3b82f6",
            width: "label",
            height: "label",
            padding: "10px",
            shape: "round-rectangle",
            "border-width": 1,
            "border-color": "#1e3a5f",
          },
        },
        {
          selector: "node[isRoot = true]",
          style: {
            "background-color": "#f97316",
            "border-width": 3,
            "border-color": "#ea580c",
          },
        },
        {
          selector: "node[isStub = true]",
          style: {
            "background-color": "#374151",
            "border-color": "#6b7280",
            "border-style": "dashed",
            shape: "ellipse",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-width": 3,
            "border-color": "#fbbf24",
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "data(lineColor)",
            "line-color": "data(lineColor)",
            "arrow-scale": 1,
          },
        },
      ],
      layout: { name: "preset" },
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.2,
    });

    for (const edge of core.edges()) {
      const kind = edge.data("kind") as string;
      edge.data("lineColor", edgeColor(kind));
    }

    if (subgraph.nodes.length <= 40) {
      core.layout({
        name: "breadthfirst",
        directed: true,
        spacingFactor: 1.4,
        roots: [`#${subgraph.rootId}`],
      }).run();
    } else {
      core.layout({
        name: "cose",
        animate: false,
        nodeRepulsion: 8000,
        idealEdgeLength: 100,
      }).run();
    }

    core.on("tap", "node", (event) => {
      const node = event.target;
      const mainId = node.data("mainGraphNodeId") as string | undefined;
      if (mainId) {
        pendingMainNodeIdRef.current = mainId;
      }
      core.nodes().unselect();
      node.select();
    });

    core.fit(undefined, 48);
    coreRef.current = core;

    return () => {
      core.destroy();
      coreRef.current = null;
    };
  }, [elements, subgraph.nodes.length, subgraph.rootId]);

  function closeModal() {
    const pending = pendingMainNodeIdRef.current;
    pendingMainNodeIdRef.current = null;
    onClose(pending ?? undefined);
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      const pending = pendingMainNodeIdRef.current;
      pendingMainNodeIdRef.current = null;
      onClose(pending ?? undefined);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  function resetDefaults() {
    const prefs = defaultCallFlowSessionPrefs();
    setDirection(prefs.direction);
    setDepth(prefs.depth);
    setDepthMode(prefs.depthMode);
    setShowExternalCalls(prefs.showExternalCalls);
  }

  function handleExportPng() {
    const core = coreRef.current;
    if (!core || subgraph.nodes.length === 0) return;
    const dataUrl = core.png({ full: true, scale: 2, bg: "#0e1116" });
    const link = document.createElement("a");
    link.href = dataUrl;
    link.download = callFlowPngFilename(root);
    link.click();
  }

  const title = callFlowDisplayLabel(root);
  const emptyDown =
    subgraph.functionCount === 1 &&
    subgraph.stubCount === 0 &&
    direction !== "upstream" &&
    subgraph.downstreamCount === 0;
  const emptyUp =
    subgraph.functionCount === 1 &&
    subgraph.stubCount === 0 &&
    direction !== "downstream" &&
    subgraph.upstreamCount === 0;

  return (
    <div
      className="sg-modal-backdrop sg-call-flow-backdrop"
      role="presentation"
      onClick={closeModal}
    >
      <div
        className="sg-call-flow-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sg-call-flow-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="sg-call-flow-modal__header">
          <h2 className="sg-call-flow-modal__title" id="sg-call-flow-title">
            Call flow: {title}
          </h2>
          <button type="button" className="sg-button sg-button--ghost" onClick={closeModal}>
            Close
          </button>
        </div>

        <div className="sg-call-flow-modal__toolbar">
          <fieldset className="sg-call-flow-modal__fieldset">
            <legend className="sg-form__hint">Direction</legend>
            {(["upstream", "both", "downstream"] as const).map((mode) => (
              <label key={mode} className="sg-call-flow-modal__radio">
                <input
                  type="radio"
                  name="call-flow-direction"
                  checked={direction === mode}
                  onChange={() => setDirection(mode)}
                />{" "}
                {mode}
              </label>
            ))}
          </fieldset>

          <label className="sg-call-flow-modal__depth">
            <span className="sg-form__hint">Depth</span>
            <select
              value={depth}
              disabled={depthMode === "full"}
              onChange={(e) => setDepth(Number(e.target.value))}
            >
              {[1, 2, 3, 4].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>

          <label className="sg-call-flow-modal__check">
            <input
              type="checkbox"
              checked={showExternalCalls}
              onChange={(e) => setShowExternalCalls(e.target.checked)}
            />{" "}
            External contract calls
          </label>

          <button
            type="button"
            className="sg-button sg-button--primary"
            onClick={() => {
              setDepthMode("full");
              setDirection("both");
            }}
          >
            Expand full chain
          </button>
          <button type="button" className="sg-button" onClick={resetDefaults}>
            Reset to default
          </button>
          <button
            type="button"
            className="sg-button"
            disabled={subgraph.nodes.length === 0}
            onClick={handleExportPng}
          >
            Export PNG
          </button>
        </div>

        {subgraph.truncated && (
          <p className="sg-banner sg-banner--info">
            Graph truncated at {options.maxNodes} functions. Use a smaller depth or
            narrow direction.
          </p>
        )}

        <p className="sg-form__hint sg-call-flow-modal__stats">
          {subgraph.functionCount} function(s)
          {subgraph.stubCount > 0 ? `, ${subgraph.stubCount} external/type stub(s)` : ""};
          upstream {subgraph.upstreamCount}, downstream {subgraph.downstreamCount}
          {depthMode === "full" ? " (full expand)" : ` (depth ${depth})`}.
          Click a node, then Close to highlight it on the main graph.
        </p>

        {(emptyDown || emptyUp) && (
          <p className="sg-banner sg-banner--info">
            No {emptyUp ? "upstream" : "downstream"} calls in this graph for the
            selected direction.
          </p>
        )}

        <div
          ref={containerRef}
          className="sg-call-flow-modal__canvas"
          role="img"
          aria-label={`Call flow diagram for ${title}`}
        />

        {subgraph.nodes.length === 0 && (
          <p className="sg-page__hint">No function nodes available for call flow.</p>
        )}
      </div>
    </div>
  );
}
