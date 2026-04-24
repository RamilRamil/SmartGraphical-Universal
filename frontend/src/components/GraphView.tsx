import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, {
  type Core,
  type ElementDefinition,
  type EventObject,
  type NodeSingular,
} from "cytoscape";
// cytoscape-cose-bilkent has no bundled types; treat as a plain plugin factory.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-expect-error no types for cytoscape-cose-bilkent
import coseBilkent from "cytoscape-cose-bilkent";

import type { GraphData, GraphNode, ModifierSwatch } from "../api/types";

let pluginRegistered = false;
function ensurePluginRegistered() {
  if (pluginRegistered) return;
  try {
    cytoscape.use(coseBilkent);
    pluginRegistered = true;
  } catch {
    pluginRegistered = true;
  }
}

function nodeColor(group: GraphNode["group"]): string {
  switch (group) {
    case "type":
      return "#2a3344";
    case "function":
      return "#3b82f6";
    case "state":
      return "#f59e0b";
    case "event":
      return "#a855f7";
    case "modifier":
      return "#22c55e";
    case "external":
      return "#6b7280";
    default:
      return "#4b5563";
  }
}

function buildElements(graph: GraphData): ElementDefinition[] {
  const nodes: ElementDefinition[] = [];
  for (const node of graph.nodes) {
    if (node.group === "function") {
      const ringDetails = node.modifier_ring_details ?? [];
      let parent = node.parent;
      for (let i = 0; i < ringDetails.length; i += 1) {
        const ring = ringDetails[i];
        if (!ring) continue;
        const ringId = `${node.id}::ring::${i}`;
        nodes.push({
          data: {
            id: ringId,
            label: "",
            group: "modifier_ring",
            parent,
            ring_color: ring.color,
            ring_name: ring.name,
            function_ref: node.id,
          },
        });
        parent = ringId;
      }
      nodes.push({
        data: {
          id: node.id,
          label: node.label,
          group: node.group,
          parent,
          kind: node.kind,
          type_name: node.type_name,
          visibility: node.visibility,
          is_entrypoint: node.is_entrypoint,
          source_body: node.source_body,
          modifier_details: node.modifier_details,
          modifier_ring_details: node.modifier_ring_details,
          modifier_color: node.modifier_color,
          calls_internal: node.calls_internal,
          calls_contract: node.calls_contract,
          calls_system: node.calls_system,
          calls_event: node.calls_event,
        },
      });
      continue;
    }
    nodes.push({
      data: {
        id: node.id,
        label: node.label,
        group: node.group,
        parent: node.parent,
        kind: node.kind,
        type_name: node.type_name,
        visibility: node.visibility,
        is_entrypoint: node.is_entrypoint,
        source_body: node.source_body,
        modifier_details: node.modifier_details,
        modifier_ring_details: node.modifier_ring_details,
        modifier_color: node.modifier_color,
        calls_internal: node.calls_internal,
        calls_contract: node.calls_contract,
        calls_system: node.calls_system,
        calls_event: node.calls_event,
      },
    });
  }
  const edges: ElementDefinition[] = graph.edges.map((edge) => ({
    data: {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      kind: edge.kind,
      label: edge.label,
    },
  }));
  return [...nodes, ...edges];
}

function readSelectedNode(node: NodeSingular): GraphNode {
  const rawMods = node.data("modifier_details");
  const modifier_details: ModifierSwatch[] | undefined = Array.isArray(rawMods)
    ? rawMods
    : undefined;
  const rawRings = node.data("modifier_ring_details");
  const modifier_ring_details: ModifierSwatch[] | undefined = Array.isArray(rawRings)
    ? rawRings
    : undefined;
  return {
    id: node.data("id"),
    label: node.data("label"),
    group: node.data("group"),
    parent: node.data("parent"),
    kind: node.data("kind"),
    type_name: node.data("type_name"),
    visibility: node.data("visibility"),
    is_entrypoint: node.data("is_entrypoint"),
    source_body: node.data("source_body"),
    modifier_details,
    modifier_ring_details,
    modifier_color: node.data("modifier_color"),
    calls_internal: node.data("calls_internal"),
    calls_contract: node.data("calls_contract"),
    calls_system: node.data("calls_system"),
    calls_event: node.data("calls_event"),
  };
}

type GraphViewProps = {
  graph: GraphData;
};

export function GraphView({ graph }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const coreRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);

  const elements = useMemo(() => buildElements(graph), [graph]);

  useEffect(() => {
    ensurePluginRegistered();
    if (!containerRef.current) return;

    const core = cytoscape({
      container: containerRef.current,
      elements,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (ele: NodeSingular) =>
              nodeColor(ele.data("group") as GraphNode["group"]),
            label: "data(label)",
            color: "#e6edf3",
            "font-size": 11,
            "text-valign": "center",
            "text-halign": "center",
            "text-outline-color": "#0e1116",
            "text-outline-width": 2,
            "border-width": 1,
            "border-color": "#0e1116",
            width: 36,
            height: 36,
          },
        },
        {
          selector: 'node[group = "function"]',
          style: {
            "border-color": (ele: NodeSingular) =>
              ele.data("is_entrypoint") ? "#f97316" : "#0e1116",
            "border-width": (ele: NodeSingular) =>
              ele.data("is_entrypoint") ? 3 : 1,
          },
        },
        {
          selector: 'node[group = "modifier_ring"]',
          style: {
            "background-opacity": 0,
            "border-width": 3,
            "border-color": "data(ring_color)",
            shape: "round-rectangle",
            padding: "4px",
            width: "label",
            height: "label",
            label: "",
            "text-opacity": 0,
          },
        },
        {
          selector: 'node[group = "type"]',
          style: {
            "background-color": "#1c2230",
            "background-opacity": 0.6,
            "border-color": "#4b5563",
            "border-width": 1,
            shape: "round-rectangle",
            "text-valign": "top",
            "text-halign": "center",
            "font-size": 12,
            "font-weight": 600,
            padding: "10px",
          },
        },
        {
          selector: 'node[group = "external"]',
          style: {
            shape: "diamond",
            width: 28,
            height: 28,
          },
        },
        {
          selector: 'node[group = "state"]',
          style: {
            shape: "ellipse",
            width: 24,
            height: 24,
          },
        },
        {
          selector: 'node[group = "event"]',
          style: {
            shape: "hexagon",
            width: 30,
            height: 30,
          },
        },
        {
          selector: 'node[group = "modifier"]',
          style: {
            shape: "round-rectangle",
            width: 34,
            height: 24,
            "background-color": "#0e1116",
            "border-width": 3,
            "border-color": (ele: NodeSingular) =>
              (ele.data("modifier_color") as string | undefined) ?? "#22c55e",
            "font-size": 10,
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#22d3ee",
            "border-width": 3,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#4b5563",
            "target-arrow-color": "#4b5563",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "font-size": 9,
            color: "#9ca3af",
            "line-style": "solid",
          },
        },
        {
          selector: 'edge[kind = "function_to_event"]',
          style: {
            "line-color": "#c084fc",
            "target-arrow-color": "#c084fc",
          },
        },
        {
          selector: 'edge[kind = "function_to_object"]',
          style: {
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b",
            "line-style": "dashed",
          },
        },
        {
          selector: 'edge[kind = "function_to_system"]',
          style: {
            "line-color": "#a78bfa",
            "target-arrow-color": "#a78bfa",
            "line-style": "dotted",
          },
        },
        {
          selector: 'edge[kind = "state_to_function"]',
          style: {
            "line-color": "#34d399",
            "target-arrow-color": "#34d399",
          },
        },
        {
          selector: 'edge[kind = "cross_type_call"]',
          style: {
            "line-color": "#f87171",
            "target-arrow-color": "#f87171",
          },
        },
        {
          selector: "edge.sg-highlighted",
          style: {
            "line-color": "#22d3ee",
            "target-arrow-color": "#22d3ee",
            width: 2.5,
            "z-index": 999,
            "line-style": "solid",
          },
        },
      ],
      layout: {
        name: "cose-bilkent",
        // @ts-expect-error cose-bilkent options are not in core typings
        animate: false,
        nodeDimensionsIncludeLabels: true,
        randomize: true,
        idealEdgeLength: 80,
        nodeRepulsion: 5000,
        tile: true,
      },
    });

    coreRef.current = core;

    core.on("tap", "node", (event: EventObject) => {
      const node = event.target;
      const group = node.data("group") as string | undefined;
      let selectedNode = node;
      if (group === "modifier_ring") {
        const functionRef = node.data("function_ref") as string | undefined;
        if (functionRef) {
          const resolved = core.getElementById(functionRef);
          if (resolved.nonempty()) {
            selectedNode = resolved;
          }
        }
      }
      core.edges().removeClass("sg-highlighted");
      selectedNode.connectedEdges().addClass("sg-highlighted");
      setSelected(readSelectedNode(selectedNode));
    });

    core.on("tap", (event: EventObject) => {
      if (event.target === core) {
        core.edges().removeClass("sg-highlighted");
        setSelected(null);
      }
    });

    return () => {
      core.destroy();
      coreRef.current = null;
    };
  }, [elements]);

  const handleExportPng = () => {
    const core = coreRef.current;
    if (!core) return;
    const dataUrl = core.png({ full: true, scale: 2, bg: "#0e1116" });
    const link = document.createElement("a");
    link.href = dataUrl;
    link.download = "smartgraphical-graph.png";
    link.click();
  };

  const handleFit = () => {
    coreRef.current?.fit(undefined, 30);
  };

  if (graph.nodes.length === 0) {
    return (
      <div className="sg-graph">
        <p className="sg-page__hint">
          Graph data is empty. Re-run the scan with task &quot;all&quot; to populate
          the graph, or this artifact may not contain any parseable structures.
        </p>
      </div>
    );
  }

  const outgoingLabels: string[] = [];
  if (selected?.group === "function") {
    if (selected.calls_internal) outgoingLabels.push("internal call");
    if (selected.calls_contract) outgoingLabels.push("external contract call");
    if (selected.calls_system) outgoingLabels.push("system / low-level call");
    if (selected.calls_event) outgoingLabels.push("emit event");
  }

  return (
    <div className="sg-graph">
      <div className="sg-graph__toolbar">
        <span className="sg-graph__stat">
          {graph.nodes.length} nodes / {graph.edges.length} edges
        </span>
        <div className="sg-graph__legend-wrap">
          <div className="sg-graph__legend">
            <span className="sg-graph__chip sg-graph__chip--type">type</span>
            <span className="sg-graph__chip sg-graph__chip--function">function</span>
            <span className="sg-graph__chip sg-graph__chip--modifier-node">modifier</span>
            <span className="sg-graph__chip sg-graph__chip--modifier">modifier ring</span>
            <span className="sg-graph__chip sg-graph__chip--state">state</span>
            <span className="sg-graph__chip sg-graph__chip--event">event</span>
            <span className="sg-graph__chip sg-graph__chip--external">external</span>
          </div>
          <div className="sg-graph__edge-legend" aria-hidden>
            <span className="sg-graph__edge-key sg-graph__edge-key--state">state</span>
            <span className="sg-graph__edge-key sg-graph__edge-key--emit">emit</span>
            <span className="sg-graph__edge-key sg-graph__edge-key--contract">ext contract</span>
            <span className="sg-graph__edge-key sg-graph__edge-key--system">system</span>
            <span className="sg-graph__edge-key sg-graph__edge-key--call">internal</span>
            <span className="sg-graph__edge-key sg-graph__edge-key--cross">cross-type</span>
          </div>
        </div>
        <div className="sg-graph__actions">
          <button
            type="button"
            className="sg-button sg-button--ghost"
            onClick={handleFit}
          >
            Fit
          </button>
          <button
            type="button"
            className="sg-button sg-button--ghost"
            onClick={handleExportPng}
          >
            Export PNG
          </button>
        </div>
      </div>
      <div className="sg-graph__canvas" ref={containerRef} />
      {selected && (
        <div className="sg-graph__details">
          <h3 className="sg-graph__details-title">
            {selected.label}{" "}
            <span className="sg-graph__group">({selected.group})</span>
          </h3>
          <dl className="sg-graph__meta">
            {selected.type_name && (
              <>
                <dt>Type</dt>
                <dd>{selected.type_name}</dd>
              </>
            )}
            {selected.visibility && (
              <>
                <dt>Visibility</dt>
                <dd>{selected.visibility}</dd>
              </>
            )}
            {selected.kind && (
              <>
                <dt>Kind</dt>
                <dd>{selected.kind}</dd>
              </>
            )}
            {selected.modifier_details && selected.modifier_details.length > 0 && (
              <>
                <dt>Modifiers</dt>
                <dd>
                  <ul className="sg-graph__modifiers">
                    {selected.modifier_details.map((m) => (
                      <li key={m.name} className="sg-graph__modifier-row">
                        <span
                          className="sg-graph__swatch"
                          style={{ background: m.color }}
                          title={m.name}
                        />
                        <span>{m.name}</span>
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            {selected.is_entrypoint && (
              <>
                <dt>Entrypoint</dt>
                <dd>yes (public or external)</dd>
              </>
            )}
            {selected.group === "function" && selected.source_body && (
              <>
                <dt>Code</dt>
                <dd>
                  <pre className="sg-graph__code">
                    <code>{selected.source_body}</code>
                  </pre>
                </dd>
              </>
            )}
            {outgoingLabels.length > 0 && (
              <>
                <dt>Outgoing (summary)</dt>
                <dd>{outgoingLabels.join(", ")}</dd>
              </>
            )}
          </dl>
        </div>
      )}
    </div>
  );
}
