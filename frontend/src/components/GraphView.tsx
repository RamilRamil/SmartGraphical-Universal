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

import type { GraphData, GraphEdge, GraphNode, ModifierSwatch } from "../api/types";

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
          full_source: node.full_source,
          modifier_details: node.modifier_details,
          modifier_ring_details: node.modifier_ring_details,
          modifier_color: node.modifier_color,
          calls_internal: node.calls_internal,
          calls_contract: node.calls_contract,
          calls_system: node.calls_system,
          calls_event: node.calls_event,
          state_reads: node.state_reads,
          state_writes: node.state_writes,
          guards: node.guards,
          write_paths: node.write_paths,
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
        full_source: node.full_source,
        modifier_details: node.modifier_details,
        modifier_ring_details: node.modifier_ring_details,
        modifier_color: node.modifier_color,
        calls_internal: node.calls_internal,
        calls_contract: node.calls_contract,
        calls_system: node.calls_system,
        calls_event: node.calls_event,
        state_reads: node.state_reads,
        state_writes: node.state_writes,
        guards: node.guards,
        write_paths: node.write_paths,
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
      callsite: edge.callsite,
      args_map: edge.args_map,
      line_numbers: edge.line_numbers,
    },
  }));
  return [...nodes, ...edges];
}

function readStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = value.filter((item): item is string => typeof item === "string");
  return items;
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
  const state_reads = readStringArray(node.data("state_reads"));
  const state_writes = readStringArray(node.data("state_writes"));
  const guards = readStringArray(node.data("guards"));
  const rawWritePaths = node.data("write_paths");
  const write_paths = Array.isArray(rawWritePaths)
    ? rawWritePaths
        .map((item) => {
          if (!item || typeof item !== "object") return null;
          const record = item as Record<string, unknown>;
          const path = typeof record.path === "string" ? record.path : "";
          const confidence =
            typeof record.confidence === "string" ? record.confidence : "unknown";
          if (!path) return null;
          return { path, confidence };
        })
        .filter((item): item is { path: string; confidence: string } => item !== null)
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
    full_source: node.data("full_source"),
    modifier_details,
    modifier_ring_details,
    modifier_color: node.data("modifier_color"),
    calls_internal: node.data("calls_internal"),
    calls_contract: node.data("calls_contract"),
    calls_system: node.data("calls_system"),
    calls_event: node.data("calls_event"),
    state_reads,
    state_writes,
    guards,
    write_paths,
  };
}

function readSelectedEdge(edge: cytoscape.EdgeSingular): GraphEdge {
  const rawArgMap = edge.data("args_map");
  const args_map = Array.isArray(rawArgMap) ? rawArgMap : [];
  const rawLineNumbers = edge.data("line_numbers");
  const line_numbers = Array.isArray(rawLineNumbers)
    ? rawLineNumbers.filter((n): n is number => typeof n === "number")
    : [];
  return {
    id: edge.data("id"),
    source: edge.data("source"),
    target: edge.data("target"),
    kind: edge.data("kind"),
    label: edge.data("label"),
    callsite: edge.data("callsite"),
    args_map,
    line_numbers,
  };
}

type GraphViewProps = {
  graph: GraphData;
};

export function GraphView({ graph }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const workspaceRef = useRef<HTMLDivElement | null>(null);
  const coreRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [highlightStateWrites, setHighlightStateWrites] = useState(false);
  const [highlightEntrypointWrites, setHighlightEntrypointWrites] = useState(false);
  const [sidePanelWidth, setSidePanelWidth] = useState(380);
  const [isResizing, setIsResizing] = useState(false);

  const elements = useMemo(() => buildElements(graph), [graph]);
  const stateWritersCount = useMemo(
    () =>
      graph.nodes.filter(
        (node) =>
          node.group === "function" &&
          Array.isArray(node.state_writes) &&
          node.state_writes.length > 0,
      ).length,
    [graph.nodes],
  );
  const entrypointWritersCount = useMemo(
    () =>
      graph.nodes.filter(
        (node) =>
          node.group === "function" &&
          Boolean(node.is_entrypoint) &&
          Array.isArray(node.state_writes) &&
          node.state_writes.length > 0,
      ).length,
    [graph.nodes],
  );
  const nodeLabelById = useMemo(() => {
    const map = new Map<string, string>();
    for (const node of graph.nodes) {
      map.set(node.id, node.label);
    }
    return map;
  }, [graph.nodes]);

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
          selector: "node.sg-state-write",
          style: {
            "border-color": "#ef4444",
            "border-width": 3,
          },
        },
        {
          selector: "node.sg-entrypoint-write",
          style: {
            "border-color": "#f97316",
            "border-width": 4,
          },
        },
        {
          selector: "node.sg-dimmed",
          style: {
            opacity: 0.2,
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
        {
          selector: "edge.sg-dimmed",
          style: {
            opacity: 0.15,
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
      setSelectedEdge(null);
    });

    core.on("tap", "edge", (event: EventObject) => {
      const edge = event.target as cytoscape.EdgeSingular;
      core.edges().removeClass("sg-highlighted");
      edge.addClass("sg-highlighted");
      setSelected(null);
      setSelectedEdge(readSelectedEdge(edge));
    });

    core.on("tap", (event: EventObject) => {
      if (event.target === core) {
        core.edges().removeClass("sg-highlighted");
        setSelected(null);
        setSelectedEdge(null);
      }
    });

    return () => {
      core.destroy();
      coreRef.current = null;
    };
  }, [elements]);

  useEffect(() => {
    const core = coreRef.current;
    if (!core) return;

    const fnNodes = core.nodes('node[group = "function"]');
    fnNodes.removeClass("sg-state-write");
    fnNodes.removeClass("sg-entrypoint-write");
    fnNodes.forEach((node) => {
      const stateWrites = node.data("state_writes");
      const isEntrypoint = Boolean(node.data("is_entrypoint"));
      if (Array.isArray(stateWrites) && stateWrites.length > 0) {
        node.addClass("sg-state-write");
        if (isEntrypoint) {
          node.addClass("sg-entrypoint-write");
        }
      }
    });

    core.nodes().removeClass("sg-dimmed");
    core.edges().removeClass("sg-dimmed");
    if (!highlightStateWrites && !highlightEntrypointWrites) return;

    core.nodes().addClass("sg-dimmed");
    core.edges().addClass("sg-dimmed");
    if (highlightEntrypointWrites) {
      core.nodes("node.sg-entrypoint-write").removeClass("sg-dimmed");
    } else {
      core.nodes("node.sg-state-write").removeClass("sg-dimmed");
    }
    core.edges().forEach((edge) => {
      const className = highlightEntrypointWrites ? "sg-entrypoint-write" : "sg-state-write";
      if (edge.source().hasClass(className) || edge.target().hasClass(className)) {
        edge.removeClass("sg-dimmed");
      }
    });
  }, [graph, highlightStateWrites, highlightEntrypointWrites]);

  const handleExportPng = () => {
    const core = coreRef.current;
    if (!core) return;
    const dataUrl = core.png({ full: true, scale: 2, bg: "#0e1116" });
    const link = document.createElement("a");
    link.href = dataUrl;
    link.download = "smartgraphical-graph.png";
    link.click();
  };

  const handleExportJson = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      graph,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "smartgraphical-graph.json";
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleFit = () => {
    coreRef.current?.fit(undefined, 30);
  };

  useEffect(() => {
    if (!isResizing) return;
    const onMouseMove = (event: MouseEvent) => {
      const workspace = workspaceRef.current;
      if (!workspace) return;
      if (window.innerWidth <= 1200) return;
      const bounds = workspace.getBoundingClientRect();
      const minPanelWidth = 280;
      const maxPanelWidth = 640;
      const next = bounds.right - event.clientX;
      const clamped = Math.max(minPanelWidth, Math.min(maxPanelWidth, next));
      setSidePanelWidth(clamped);
    };
    const onMouseUp = () => setIsResizing(false);
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [isResizing]);

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
        <span className="sg-graph__stat">
          state-writers: {stateWritersCount}
        </span>
        <span className="sg-graph__stat">
          entrypoint-writers: {entrypointWritersCount}
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
          <button
            type="button"
            className="sg-button sg-button--ghost"
            onClick={handleExportJson}
          >
            Export JSON
          </button>
          <button
            type="button"
            className="sg-button sg-button--ghost"
            onClick={() => {
              setHighlightStateWrites((value) => !value);
              setHighlightEntrypointWrites(false);
            }}
          >
            {highlightStateWrites ? "Show all nodes" : "Highlight state writes"}
          </button>
          <button
            type="button"
            className="sg-button sg-button--ghost"
            onClick={() => {
              setHighlightEntrypointWrites((value) => !value);
              if (!highlightEntrypointWrites) {
                setHighlightStateWrites(false);
              }
            }}
          >
            {highlightEntrypointWrites
              ? "Show all nodes"
              : "Only entrypoints writing state"}
          </button>
        </div>
      </div>
      <div
        className="sg-graph__workspace"
        ref={workspaceRef}
        style={{ ["--sg-side-width" as string]: `${sidePanelWidth}px` }}
      >
        <div className="sg-graph__canvas" ref={containerRef} />
        <div
          className={`sg-graph__splitter${isResizing ? " sg-graph__splitter--active" : ""}`}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize graph details panel"
          onMouseDown={() => setIsResizing(true)}
        />
        <div className="sg-graph__side">
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
                {selected.group === "function" && (selected.full_source || selected.source_body) && (
                  <>
                    <dt>Code</dt>
                    <dd>
                      <pre className="sg-graph__code">
                        <code>{selected.full_source || selected.source_body}</code>
                      </pre>
                    </dd>
                  </>
                )}
                {selected.group === "function" && selected.state_reads && selected.state_reads.length > 0 && (
                  <>
                    <dt>State reads</dt>
                    <dd>{selected.state_reads.join(", ")}</dd>
                  </>
                )}
                {selected.group === "function" &&
                  selected.state_writes &&
                  selected.state_writes.length > 0 && (
                    <>
                      <dt>State writes</dt>
                      <dd>
                        <ul className="sg-graph__modifiers">
                          {selected.state_writes.map((item, index) => (
                            <li key={`${item}-${index}`} className="sg-graph__modifier-row">
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </dd>
                    </>
                  )}
                {selected.group === "function" && selected.guards && selected.guards.length > 0 && (
                  <>
                    <dt>Guards (summary)</dt>
                    <dd>
                      <ul className="sg-graph__modifiers">
                        {selected.guards.map((guard, index) => (
                          <li key={`${guard}-${index}`} className="sg-graph__modifier-row">
                            <span>{guard}</span>
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
                {selected.group === "function" &&
                  selected.write_paths &&
                  selected.write_paths.length > 0 && (
                    <>
                      <dt>Write paths</dt>
                      <dd>
                        <ul className="sg-graph__modifiers">
                          {selected.write_paths.map((item, index) => (
                            <li
                              key={`${item.path}-${index}`}
                              className="sg-graph__modifier-row"
                            >
                              <span>{item.path}</span>
                              <span>{`(${item.confidence})`}</span>
                            </li>
                          ))}
                        </ul>
                      </dd>
                    </>
                  )}
                {selected.group === "state" && selected.kind === "struct" && selected.source_body && (
                  <>
                    <dt>Struct fields</dt>
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
          {selectedEdge && (
            <div className="sg-graph__details">
              <h3 className="sg-graph__details-title">
                Edge{" "}
                <span className="sg-graph__group">({selectedEdge.kind || "unknown"})</span>
              </h3>
              <dl className="sg-graph__meta">
                <dt>From</dt>
                <dd>{nodeLabelById.get(selectedEdge.source) ?? selectedEdge.source}</dd>
                <dt>To</dt>
                <dd>{nodeLabelById.get(selectedEdge.target) ?? selectedEdge.target}</dd>
                {selectedEdge.label && (
                  <>
                    <dt>Label</dt>
                    <dd>{selectedEdge.label}</dd>
                  </>
                )}
                {selectedEdge.callsite && (
                  <>
                    <dt>Callsite</dt>
                    <dd>
                      <pre className="sg-graph__code">
                        <code>{selectedEdge.callsite}</code>
                      </pre>
                    </dd>
                  </>
                )}
                {selectedEdge.line_numbers && selectedEdge.line_numbers.length > 0 && (
                  <>
                    <dt>Lines</dt>
                    <dd>{selectedEdge.line_numbers.join(", ")}</dd>
                  </>
                )}
                {selectedEdge.args_map && selectedEdge.args_map.length > 0 && (
                  <>
                    <dt>Args</dt>
                    <dd>
                      <ul className="sg-graph__modifiers">
                        {selectedEdge.args_map.map((arg, index) => (
                          <li key={`${arg.param}-${index}`} className="sg-graph__modifier-row">
                            <span>{arg.param}</span>
                            <span>{" <- "}</span>
                            <span>{arg.value}</span>
                            {arg.source_kind && <span>{`(${arg.source_kind})`}</span>}
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
              </dl>
            </div>
          )}
          {!selected && !selectedEdge && (
            <div className="sg-graph__details">
              <p className="sg-page__hint">
                Select a node or edge to inspect metadata, state writes, and dataflow.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
