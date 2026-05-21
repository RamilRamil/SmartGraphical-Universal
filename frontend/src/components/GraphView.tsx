import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, {
  type Core,
  type EdgeSingular,
  type ElementDefinition,
  type EventObject,
  type NodeSingular,
} from "cytoscape";
// cytoscape-cose-bilkent has no bundled types; treat as a plain plugin factory.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-expect-error no types for cytoscape-cose-bilkent
import coseBilkent from "cytoscape-cose-bilkent";

import type { GraphData, GraphEdge, GraphNode, ModifierSwatch } from "../api/types";
import { buildFocusNodeSet, buildFocusSecondaryEdgeIds } from "../graph/focusNeighborhood";
import {
  edgeIdsDroppedAsRedundantBundleLinks,
  filterFullGraphEdges,
  FULL_GRAPH_EXTERNAL_EDGE_KINDS,
  INTER_CONTRACT_EDGE_KINDS,
  isTypeCompoundInterContractEdge,
  toInterContractOverviewGraph,
} from "../graph/interContractOverview";

/** Bundled cytoscape typings omit eles.show/hide (present at runtime). */
type CyElements = ReturnType<Core["elements"]>;
type CyElementsVisibility = CyElements & {
  show(): CyElements;
  hide(): CyElements;
};

type LegendNodeBucket =
  | "type_tile"
  | "abstract"
  | "interface"
  | "library"
  | "function"
  | "modifier"
  | "modifier_ring"
  | "state_workspace"
  | "event"
  | "custom_error"
  | "external";

type LegendEdgeBucket =
  | "edge_state"
  | "edge_emit"
  | "edge_revert_error"
  | "edge_ext_contract"
  | "edge_system"
  | "edge_internal"
  | "edge_cross_type"
  | "edge_include_c"
  | "edge_struct_ws";

type HiddenLegend = Partial<Record<LegendNodeBucket | LegendEdgeBucket, true>>;

/** Edges that mean a function writes contract storage (not reads). */
const STATE_WRITE_EDGE_KINDS = new Set([
  "state_to_function_write",
  "cross_type_state_write",
]);

type EdgeLegendToggle = {
  bucket: LegendEdgeBucket;
  label: string;
  className?: string;
  style?: React.CSSProperties;
};

type EdgeLegendGuideRow = {
  label: string;
  description: string;
  sampleClassName?: string;
  sampleStyle?: React.CSSProperties;
};

const EDGE_TOGGLE_ENTRIES: EdgeLegendToggle[] = [
  { bucket: "edge_state", label: "state", className: "sg-graph__edge-key--state" },
  { bucket: "edge_emit", label: "emit", className: "sg-graph__edge-key--emit" },
  { bucket: "edge_revert_error", label: "revert error", style: { color: "#f87171" } },
  { bucket: "edge_ext_contract", label: "ext contract", className: "sg-graph__edge-key--contract" },
  { bucket: "edge_system", label: "system", className: "sg-graph__edge-key--system" },
  { bucket: "edge_internal", label: "internal", className: "sg-graph__edge-key--call" },
  { bucket: "edge_cross_type", label: "cross-type", className: "sg-graph__edge-key--cross" },
  { bucket: "edge_include_c", label: "inc .c", style: { color: "#2dd4bf" } },
  { bucket: "edge_struct_ws", label: "struct/workspace", style: { color: "#fb923c" } },
];

const EDGE_GUIDE_ROWS: EdgeLegendGuideRow[] = [
  {
    label: "State read",
    description: "State variable to function that reads storage (solid green).",
    sampleClassName: "sg-graph__edge-key--state",
  },
  {
    label: "State write",
    description: "State variable to function that may write storage (dashed orange).",
    sampleClassName: "sg-graph__edge-key--state",
    sampleStyle: { borderLeftColor: "#f59e0b", borderLeftStyle: "dashed" },
  },
  {
    label: "Emit",
    description: "Function to Solidity event it emits.",
    sampleClassName: "sg-graph__edge-key--emit",
  },
  {
    label: "Revert error",
    description: "Function to user-defined error used on revert.",
    sampleStyle: { borderLeftColor: "#f87171" },
  },
  {
    label: "External contract",
    description: "Function to external type or cross-file contract call (dashed).",
    sampleClassName: "sg-graph__edge-key--contract",
  },
  {
    label: "System",
    description: "Function to built-in or runtime call (dotted).",
    sampleClassName: "sg-graph__edge-key--system",
  },
  {
    label: "Internal",
    description: "Call between functions in the same contract.",
    sampleClassName: "sg-graph__edge-key--call",
  },
  {
    label: "Cross-type",
    description:
      "Between contracts in a bundle: inheritance, parent calls, shared state (red). Shown in Inter-contract view.",
    sampleClassName: "sg-graph__edge-key--cross",
  },
  {
    label: "Import (C)",
    description: "C translation unit includes another bundle file.",
    sampleStyle: { borderLeftColor: "#2dd4bf" },
  },
  {
    label: "Struct / workspace",
    description: "Function uses struct or workspace entity (C profile).",
    sampleStyle: { borderLeftColor: "#fb923c" },
  },
];

function bucketForNode(node: NodeSingular): LegendNodeBucket | null {
  const g = node.data("group") as GraphNode["group"] | undefined;
  if (!g) return null;
  if (g === "tile") return "type_tile";
  if (g === "type") {
    const sk = node.data("solidity_kind") as GraphNode["solidity_kind"] | undefined;
    if (sk === "abstract") return "abstract";
    if (sk === "interface") return "interface";
    if (sk === "library") return "library";
    return "type_tile";
  }
  if (g === "function") return "function";
  if (g === "modifier_ring") return "modifier_ring";
  if (g === "modifier") return "modifier";
  if (g === "state" || g === "workspace") return "state_workspace";
  if (g === "event") return "event";
  if (g === "custom_error") return "custom_error";
  if (g === "external" || g === "external_import") return "external";
  return null;
}

function bucketForEdgeKind(kind: string): LegendEdgeBucket | null {
  switch (kind) {
    case "state_to_function":
    case "state_to_function_read":
    case "state_to_function_write":
      return "edge_state";
    case "function_to_event":
      return "edge_emit";
    case "function_to_custom_error":
      return "edge_revert_error";
    case "function_to_object":
    case "cross_contract_call":
      return "edge_ext_contract";
    case "function_to_system":
      return "edge_system";
    case "function_to_function":
      return "edge_internal";
    case "cross_type_call":
    case "cross_type_state":
    case "cross_type_state_read":
    case "cross_type_state_write":
      return "edge_cross_type";
    case "function_to_include_template":
      return "edge_include_c";
    case "function_to_workspace":
      return "edge_struct_ws";
    default:
      return null;
  }
}

function isLegendHidden(hidden: HiddenLegend, key: string | null): boolean {
  if (!key) return false;
  return hidden[key as keyof HiddenLegend] === true;
}

type GraphVisibilityOpts = {
  hiddenLegend: HiddenLegend;
  showImports: boolean;
  showCrossContractCalls: boolean;
  interContractOnly: boolean;
  hiddenRedundantBundleImportIds: Set<string>;
  focusNodeIds: Set<string> | null;
};

function applyGraphVisibility(core: Core, opts: GraphVisibilityOpts): void {
  const {
    hiddenLegend,
    showImports,
    showCrossContractCalls,
    interContractOnly,
    hiddenRedundantBundleImportIds,
    focusNodeIds,
  } = opts;

  const nodeBaseVisible = (node: NodeSingular): boolean => {
    const g = node.data("group") as string | undefined;
    const bucket = bucketForNode(node);
    let ok = !isLegendHidden(hiddenLegend, bucket);
    if (g === "modifier_ring" && isLegendHidden(hiddenLegend, "function")) ok = false;
    if (g === "external_import" && !showImports) ok = false;
    return ok;
  };

  const nodeVisible = (node: NodeSingular): boolean => {
    const id = node.id();
    if (focusNodeIds?.has(id)) {
      if (node.data("group") === "external_import" && !showImports) return false;
      return true;
    }
    return nodeBaseVisible(node);
  };

  core.nodes().forEach((ele) => {
    const node = ele as NodeSingular;
    const cy = node as unknown as CyElementsVisibility;
    if (nodeVisible(node)) cy.show();
    else cy.hide();
  });

  core.edges().forEach((ele) => {
    const edge = ele as EdgeSingular;
    const kind = String(edge.data("kind") ?? "");
    const eBucket = bucketForEdgeKind(kind);
    let ok = !isLegendHidden(hiddenLegend, eBucket);

    if (kind === "import_dependency" && !showImports) ok = false;
    if (!interContractOnly) {
      if (isTypeCompoundCrossEdgeEle(edge)) {
        ok = false;
      } else if (!showCrossContractCalls) {
        if (INTER_CONTRACT_EDGE_KINDS.has(kind)) {
          ok = false;
        } else if (FULL_GRAPH_EXTERNAL_EDGE_KINDS.has(kind)) {
          ok = false;
        }
      }
    }
    if (hiddenRedundantBundleImportIds.has(edge.id())) {
      ok = false;
    }

    const src = edge.source();
    const tgt = edge.target();
    if (!nodeVisible(src as NodeSingular) || !nodeVisible(tgt as NodeSingular)) ok = false;

    const cy = edge as unknown as CyElementsVisibility;
    if (ok) {
      cy.show();
      edge.removeClass("sg-view-suppressed");
    } else {
      cy.hide();
      edge.addClass("sg-view-suppressed");
    }
  });
}

function isTypeCompoundCrossEdgeEle(edge: EdgeSingular): boolean {
  const kind = String(edge.data("kind") ?? "");
  if (!INTER_CONTRACT_EDGE_KINDS.has(kind)) {
    return false;
  }
  if (
    edge.source().data("group") === "type" &&
    edge.target().data("group") === "type"
  ) {
    return true;
  }
  return String(edge.data("label") ?? "").startsWith("extends ");
}

function crossContractEdgesInCore(core: Core): ReturnType<Core["edges"]> {
  return core.edges().filter((ele) => {
    const edge = ele as EdgeSingular;
    if (isTypeCompoundCrossEdgeEle(edge)) {
      return false;
    }
    const kind = String(edge.data("kind") ?? "");
    return (
      INTER_CONTRACT_EDGE_KINDS.has(kind) ||
      FULL_GRAPH_EXTERNAL_EDGE_KINDS.has(kind)
    );
  });
}

/** Resize canvas to container; preserves pan/zoom (no fit). */
function scheduleGraphResize(core: Core | null): void {
  if (!core) return;
  requestAnimationFrame(() => {
    core.resize();
  });
}

function requestGraphFullscreen(el: HTMLElement): Promise<void> {
  const req = el.requestFullscreen?.bind(el);
  if (typeof req === "function") return req();
  const legacy = (el as HTMLElement & { webkitRequestFullscreen?: () => void }).webkitRequestFullscreen;
  if (typeof legacy === "function") {
    legacy.call(el);
    return Promise.resolve();
  }
  return Promise.reject(new Error("fullscreen unavailable"));
}

function exitGraphFullscreen(): Promise<void> {
  if (document.fullscreenElement && document.exitFullscreen) {
    return document.exitFullscreen();
  }
  const doc = document as Document & { webkitExitFullscreen?: () => Promise<void> };
  if (doc.webkitExitFullscreen) return doc.webkitExitFullscreen();
  return Promise.resolve();
}

function isGraphShellFullscreen(shell: HTMLElement): boolean {
  if (document.fullscreenElement === shell) return true;
  const doc = document as Document & { webkitFullscreenElement?: Element | null };
  return doc.webkitFullscreenElement === shell;
}

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
    case "tile":
      return "#2a3344";
    case "function":
      return "#3b82f6";
    case "state":
    case "workspace":
      return "#f59e0b";
    case "event":
      return "#a855f7";
    case "custom_error":
      return "#ef4444";
    case "modifier":
      return "#22c55e";
    case "external":
      return "#6b7280";
    case "external_import":
      return "#6366f1";
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
          solidity_kind: node.solidity_kind,
          calls_internal: node.calls_internal,
          calls_contract: node.calls_contract,
          calls_system: node.calls_system,
          calls_event: node.calls_event,
          calls_custom_error: node.calls_custom_error,
          calls_include_template: node.calls_include_template,
          heuristic_callees_ordered: node.heuristic_callees_ordered,
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
        variable_type: node.variable_type,
        storage_attributes: node.storage_attributes,
        import_path: node.import_path,
        resolution: node.resolution,
        type_name: node.type_name,
        visibility: node.visibility,
        is_entrypoint: node.is_entrypoint,
        source_body: node.source_body,
        full_source: node.full_source,
        modifier_details: node.modifier_details,
        modifier_ring_details: node.modifier_ring_details,
        modifier_color: node.modifier_color,
        solidity_kind: node.solidity_kind,
        calls_internal: node.calls_internal,
        calls_contract: node.calls_contract,
        calls_system: node.calls_system,
        calls_event: node.calls_event,
        calls_custom_error: node.calls_custom_error,
        calls_include_template: node.calls_include_template,
        state_reads: node.state_reads,
        state_writes: node.state_writes,
        guards: node.guards,
        write_paths: node.write_paths,
        source_file: node.source_file,
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
      import_symbol: edge.import_symbol,
      import_path: edge.import_path ?? edge.label,
      resolution: edge.resolution,
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
    variable_type: node.data("variable_type"),
    storage_attributes: readStringArray(node.data("storage_attributes")),
    import_path: node.data("import_path"),
    resolution: node.data("resolution"),
    source_file: node.data("source_file"),
    type_name: node.data("type_name"),
    solidity_kind: node.data("solidity_kind") as GraphNode["solidity_kind"],
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
    calls_custom_error: node.data("calls_custom_error"),
    calls_include_template: Boolean(node.data("calls_include_template")),
    heuristic_callees_ordered: readStringArray(node.data("heuristic_callees_ordered")),
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
    import_symbol: edge.data("import_symbol"),
    import_path: edge.data("import_path"),
    resolution: edge.data("resolution"),
  };
}

type GraphViewProps = {
  graph: GraphData;
};

export function GraphView({ graph }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const workspaceRef = useRef<HTMLDivElement | null>(null);
  const toolbarWrapRef = useRef<HTMLDivElement | null>(null);
  const coreRef = useRef<Core | null>(null);
  const prevShowCrossContractCallsRef = useRef(false);
  const fullscreenShellRef = useRef<HTMLDivElement | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [highlightStateWrites, setHighlightStateWrites] = useState(false);
  const [highlightEntrypointWrites, setHighlightEntrypointWrites] = useState(false);
  const [showImports, setShowImports] = useState(false);
  const [showCrossContractCalls, setShowCrossContractCalls] = useState(false);
  const [interContractOnly, setInterContractOnly] = useState(false);
  const [sidePanelWidth, setSidePanelWidth] = useState(380);
  const [isResizing, setIsResizing] = useState(false);
  const [isResizingToolbar, setIsResizingToolbar] = useState(false);
  /** Cap for toolbar+legend scroll area; content can be shorter. */
  const [toolbarPanelHeight, setToolbarPanelHeight] = useState(280);
  const [isGraphFullscreen, setIsGraphFullscreen] = useState(false);
  const [hiddenLegend, setHiddenLegend] = useState<HiddenLegend>(() => ({}));
  const [focusSelectionEnabled, setFocusSelectionEnabled] = useState(false);
  const [graphCanvasOnly, setGraphCanvasOnly] = useState(false);

  useEffect(() => {
    setHiddenLegend({});
    setFocusSelectionEnabled(false);
    setGraphCanvasOnly(false);
  }, [graph]);

  useEffect(() => {
    if (interContractOnly) {
      return;
    }
    const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
    setSelectedEdge((edge) => {
      if (!edge) {
        return edge;
      }
      if (
        INTER_CONTRACT_EDGE_KINDS.has(edge.kind) &&
        (!showCrossContractCalls ||
          (edge.source &&
            edge.target &&
            isTypeCompoundInterContractEdge(edge, nodeById)))
      ) {
        return null;
      }
      return edge;
    });
  }, [interContractOnly, graph, showCrossContractCalls]);

  const toggleLegend = (key: LegendNodeBucket | LegendEdgeBucket) => {
    setHiddenLegend((prev) => {
      const next = { ...prev };
      if (next[key]) delete next[key];
      else next[key] = true;
      return next;
    });
  };

  const structureGraph = useMemo(() => {
    if (interContractOnly) {
      return toInterContractOverviewGraph(graph);
    }
    return graph;
  }, [graph, interContractOnly]);

  const displayGraph = useMemo(() => {
    if (interContractOnly) {
      return structureGraph;
    }
    return filterFullGraphEdges(graph, showCrossContractCalls);
  }, [graph, interContractOnly, showCrossContractCalls, structureGraph]);

  const hiddenRedundantBundleImportIds = useMemo(
    () =>
      interContractOnly || !showCrossContractCalls
        ? new Set<string>()
        : edgeIdsDroppedAsRedundantBundleLinks(graph.edges),
    [graph.edges, interContractOnly, showCrossContractCalls],
  );

  const elements = useMemo(() => buildElements(structureGraph), [structureGraph]);
  const stateWriteTargets = useMemo(() => {
    const functionIds = new Set<string>();
    const stateIds = new Set<string>();
    const edgeIds = new Set<string>();
    for (const edge of displayGraph.edges) {
      if (!STATE_WRITE_EDGE_KINDS.has(edge.kind)) {
        continue;
      }
      edgeIds.add(edge.id);
      functionIds.add(edge.target);
      stateIds.add(edge.source);
    }
    if (functionIds.size === 0) {
      for (const node of displayGraph.nodes) {
        if (
          node.group === "function" &&
          Array.isArray(node.state_writes) &&
          node.state_writes.length > 0
        ) {
          functionIds.add(node.id);
        }
      }
    }
    return { functionIds, stateIds, edgeIds };
  }, [displayGraph.edges, displayGraph.nodes]);

  const stateWritersCount = stateWriteTargets.functionIds.size;

  const entrypointWritersCount = useMemo(() => {
    let count = 0;
    for (const node of displayGraph.nodes) {
      if (
        node.group === "function" &&
        Boolean(node.is_entrypoint) &&
        stateWriteTargets.functionIds.has(node.id)
      ) {
        count += 1;
      }
    }
    return count;
  }, [displayGraph.nodes, stateWriteTargets.functionIds]);
  const nodeLabelById = useMemo(() => {
    const map = new Map<string, string>();
    for (const node of displayGraph.nodes) {
      map.set(node.id, node.label);
    }
    return map;
  }, [displayGraph.nodes]);

  const selectedImportUsages = useMemo(() => {
    if (!selected || selected.group !== "function") return [];
    const rows: Array<{
      symbol: string;
      path: string;
      lines: string;
      callsite: string;
      targetLabel: string;
    }> = [];
    for (const edge of displayGraph.edges) {
      if (edge.kind !== "import_dependency" || edge.source !== selected.id) continue;
      rows.push({
        symbol: edge.import_symbol ?? edge.label,
        path: edge.import_path ?? edge.label,
        lines: edge.line_numbers?.length ? edge.line_numbers.join(", ") : "",
        callsite: edge.callsite ?? "",
        targetLabel: nodeLabelById.get(edge.target) ?? edge.target,
      });
    }
    return rows;
  }, [displayGraph.edges, selected, nodeLabelById]);

  const selectedExternalImportUsages = useMemo(() => {
    if (!selected || selected.group !== "external_import") return [];
    const rows: Array<{
      fromLabel: string;
      fromId: string;
      lines: string;
      callsite: string;
    }> = [];
    for (const edge of displayGraph.edges) {
      if (edge.kind !== "import_dependency" || edge.target !== selected.id) continue;
      rows.push({
        fromLabel: nodeLabelById.get(edge.source) ?? edge.source,
        fromId: edge.source,
        lines: edge.line_numbers?.length ? edge.line_numbers.join(", ") : "",
        callsite: edge.callsite ?? "",
      });
    }
    return rows;
  }, [displayGraph.edges, selected, nodeLabelById]);

  const stateReaderFunctionLabels = useMemo(() => {
    if (!selected || (selected.group !== "state" && selected.group !== "workspace")) {
      return [];
    }
    const readKinds = new Set([
      "state_to_function",
      "state_to_function_read",
      "cross_type_state_read",
    ]);
    const labels: string[] = [];
    for (const edge of displayGraph.edges) {
      if (!readKinds.has(edge.kind) || edge.source !== selected.id) {
        continue;
      }
      labels.push(nodeLabelById.get(edge.target) ?? edge.target);
    }
    return [...new Set(labels)].sort((a, b) => a.localeCompare(b));
  }, [displayGraph.edges, selected, nodeLabelById]);

  const stateWriterFunctionLabels = useMemo(() => {
    if (!selected || (selected.group !== "state" && selected.group !== "workspace")) {
      return [];
    }
    const writeKinds = new Set([
      "state_to_function_write",
      "cross_type_state_write",
    ]);
    const labels: string[] = [];
    for (const edge of displayGraph.edges) {
      if (!writeKinds.has(edge.kind) || edge.source !== selected.id) {
        continue;
      }
      labels.push(nodeLabelById.get(edge.target) ?? edge.target);
    }
    return [...new Set(labels)].sort((a, b) => a.localeCompare(b));
  }, [displayGraph.edges, selected, nodeLabelById]);

  const focusEligible =
    selected !== null && (selected.group === "type" || selected.group === "tile");

  const focusNodeIds = useMemo(
    () =>
      buildFocusNodeSet(
        displayGraph,
        selected?.id ?? null,
        focusSelectionEnabled && focusEligible,
      ),
    [displayGraph, selected?.id, focusSelectionEnabled, focusEligible],
  );

  const focusSecondaryEdgeIds = useMemo(() => {
    if (!focusNodeIds || !selected?.id) return null;
    return buildFocusSecondaryEdgeIds(displayGraph, selected.id, focusNodeIds);
  }, [displayGraph, focusNodeIds, selected?.id]);

  const graphVisibilityOpts = useMemo<GraphVisibilityOpts>(
    () => ({
      hiddenLegend,
      showImports,
      showCrossContractCalls,
      interContractOnly,
      hiddenRedundantBundleImportIds,
      focusNodeIds,
    }),
    [
      hiddenLegend,
      showImports,
      showCrossContractCalls,
      interContractOnly,
      hiddenRedundantBundleImportIds,
      focusNodeIds,
    ],
  );
  const graphVisibilityOptsRef = useRef(graphVisibilityOpts);
  graphVisibilityOptsRef.current = graphVisibilityOpts;

  useEffect(() => {
    if (!focusSelectionEnabled) return;
    if (!selected || (selected.group !== "type" && selected.group !== "tile")) {
      setFocusSelectionEnabled(false);
    }
  }, [selected, focusSelectionEnabled]);

  useEffect(() => {
    ensurePluginRegistered();
    if (!containerRef.current) return;

    const overviewLayout = interContractOnly;

    const layoutOptions = overviewLayout
      ? {
          name: "cose-bilkent" as const,
          animate: false,
          nodeDimensionsIncludeLabels: true,
          randomize: true,
          idealEdgeLength: 170,
          nodeRepulsion: 22000,
          gravity: 0.4,
          nestingFactor: 0.04,
          tile: true,
        }
      : {
          name: "cose-bilkent" as const,
          animate: false,
          nodeDimensionsIncludeLabels: true,
          randomize: true,
          idealEdgeLength: 80,
          nodeRepulsion: 5000,
          tile: true,
        };

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
          selector: 'node[group = "type"], node[group = "tile"]',
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
          selector: 'node[group = "type"][solidity_kind = "abstract"]',
          style: {
            "border-color": "#c084fc",
            "border-width": 3,
          },
        },
        {
          selector: 'node[group = "type"][solidity_kind = "interface"]',
          style: {
            "border-color": "#22d3ee",
            "border-width": 3,
          },
        },
        {
          selector: 'node[group = "type"][solidity_kind = "library"]',
          style: {
            "border-color": "#fbbf24",
            "border-width": 3,
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
          selector: 'node[group = "external_import"]',
          style: {
            shape: "diamond",
            width: 32,
            height: 32,
          },
        },
        {
          selector: 'node[group = "state"], node[group = "workspace"]',
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
          selector: 'node[group = "custom_error"]',
          style: {
            shape: "octagon",
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
            "border-color": "#818cf8",
            "border-width": 4,
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
          selector: 'edge[kind = "function_to_include_template"]',
          style: {
            "line-color": "#2dd4bf",
            "target-arrow-color": "#2dd4bf",
            "line-style": "dashed",
          },
        },
        {
          selector: 'edge[kind = "function_to_workspace"]',
          style: {
            "line-color": "#fb923c",
            "target-arrow-color": "#fb923c",
            "line-style": "dotted",
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
          selector: 'edge[kind = "function_to_custom_error"]',
          style: {
            "line-color": "#f87171",
            "target-arrow-color": "#f87171",
            "line-style": "dashed",
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
          selector: 'edge[kind = "cross_contract_call"]',
          style: {
            "line-color": "#f97316",
            "target-arrow-color": "#f97316",
            width: 2.5,
          },
        },
        {
          selector: 'edge[kind = "import_dependency"]',
          style: {
            "line-color": "#6366f1",
            "target-arrow-color": "#6366f1",
            "line-style": "dashed",
            width: 1,
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
          selector: 'edge[kind = "state_to_function"], edge[kind = "state_to_function_read"]',
          style: {
            "line-color": "#34d399",
            "target-arrow-color": "#34d399",
          },
        },
        {
          selector: 'edge[kind = "state_to_function_write"]',
          style: {
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b",
            "line-style": "dashed",
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
          selector: "edge.sg-focus-edge-2",
          style: {
            opacity: 0.42,
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
            opacity: 1,
          },
        },
        {
          selector: "edge.sg-dimmed",
          style: {
            opacity: 0.15,
          },
        },
        {
          selector: "edge.sg-view-suppressed",
          style: {
            opacity: 0,
            "z-index": -1,
            events: "no",
          },
        },
      ],
      layout: layoutOptions,
    });

    coreRef.current = core;

    const fitPadding = overviewLayout ? 56 : 36;
    const applyFit = () => {
      core.resize();
      core.fit(undefined, fitPadding);
    };
    applyFit();
    requestAnimationFrame(applyFit);

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
      selectedNode
        .connectedEdges()
        .filter((e: EdgeSingular) => e.visible())
        .addClass("sg-highlighted");
      setSelected(readSelectedNode(selectedNode));
      setSelectedEdge(null);
    });

    core.on("tap", "edge", (event: EventObject) => {
      const edge = event.target as EdgeSingular;
      if (!edge.visible()) {
        return;
      }
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

    applyGraphVisibility(core, graphVisibilityOptsRef.current);

    return () => {
      core.destroy();
      coreRef.current = null;
    };
  }, [elements, interContractOnly]);

  useEffect(() => {
    const core = coreRef.current;
    if (!core) return;

    const fnNodes = core.nodes('node[group = "function"]');
    fnNodes.removeClass("sg-state-write");
    fnNodes.removeClass("sg-entrypoint-write");
    fnNodes.forEach((node) => {
      const nodeId = node.id();
      if (!stateWriteTargets.functionIds.has(nodeId)) {
        return;
      }
      node.addClass("sg-state-write");
      if (Boolean(node.data("is_entrypoint"))) {
        node.addClass("sg-entrypoint-write");
      }
    });

    core.nodes().removeClass("sg-dimmed");
    core.edges().removeClass("sg-dimmed");
    if (!highlightStateWrites && !highlightEntrypointWrites) return;

    core.nodes().addClass("sg-dimmed");
    core.edges().addClass("sg-dimmed");

    const showWriter = (nodeId: string) => {
      const node = core.getElementById(nodeId);
      if (!node.empty()) {
        node.removeClass("sg-dimmed");
      }
    };

    if (highlightEntrypointWrites) {
      fnNodes.forEach((node) => {
        if (node.hasClass("sg-entrypoint-write")) {
          node.removeClass("sg-dimmed");
        }
      });
    } else if (highlightStateWrites) {
      stateWriteTargets.functionIds.forEach(showWriter);
      stateWriteTargets.stateIds.forEach(showWriter);
    }

    stateWriteTargets.edgeIds.forEach((edgeId) => {
      const edge = core.getElementById(edgeId);
      if (edge.empty()) {
        return;
      }
      if (highlightEntrypointWrites) {
        if (!edge.target().hasClass("sg-entrypoint-write")) {
          return;
        }
      } else if (!highlightStateWrites) {
        return;
      }
      edge.removeClass("sg-dimmed");
    });
  }, [
    displayGraph,
    highlightStateWrites,
    highlightEntrypointWrites,
    hiddenLegend,
    focusNodeIds,
    stateWriteTargets,
  ]);

  useEffect(() => {
    const core = coreRef.current;
    if (!core) return;
    applyGraphVisibility(core, graphVisibilityOpts);
    const turnedOn =
      showCrossContractCalls &&
      !prevShowCrossContractCallsRef.current &&
      !interContractOnly;
    prevShowCrossContractCallsRef.current = showCrossContractCalls;
    if (turnedOn) {
      const cross = crossContractEdgesInCore(core);
      if (cross.length > 0) {
        requestAnimationFrame(() => {
          core.fit(cross, 48);
        });
      }
    }
    setSelected((sel) => {
      if (!sel) return sel;
      const n = core.getElementById(sel.id);
      if (n.empty() || !n.visible()) return null;
      return sel;
    });
    setSelectedEdge((edge) => {
      if (!edge) return edge;
      const e = core.getElementById(edge.id);
      if (e.empty() || !e.visible()) return null;
      return edge;
    });
  }, [graphVisibilityOpts, showCrossContractCalls, interContractOnly]);

  useEffect(() => {
    const core = coreRef.current;
    if (!core) return;
    core.edges().removeClass("sg-focus-edge-2");
    if (!focusSecondaryEdgeIds) return;
    for (const edgeId of focusSecondaryEdgeIds) {
      const el = core.getElementById(edgeId);
      if (!el.empty()) el.addClass("sg-focus-edge-2");
    }
  }, [elements, focusSecondaryEdgeIds]);

  useEffect(() => {
    scheduleGraphResize(coreRef.current);
  }, [graphCanvasOnly]);

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
      graph: displayGraph,
      view: interContractOnly ? "inter_contract" : "full",
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
      scheduleGraphResize(coreRef.current);
    };
    const onMouseUp = () => setIsResizing(false);
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [isResizing]);

  useEffect(() => {
    if (!isResizingToolbar) return;
    const onMouseMove = (event: MouseEvent) => {
      if (window.innerWidth <= 1200) return;
      const wrap = toolbarWrapRef.current;
      const shell = fullscreenShellRef.current;
      if (!wrap || !shell) return;
      const top = wrap.getBoundingClientRect().top;
      const next = event.clientY - top;
      const shellH = shell.getBoundingClientRect().height;
      const minToolbar = 120;
      const reserveWorkspace = 200;
      const maxToolbar = Math.max(minToolbar + 40, shellH - reserveWorkspace);
      setToolbarPanelHeight(Math.max(minToolbar, Math.min(maxToolbar, next)));
      scheduleGraphResize(coreRef.current);
    };
    const onMouseUp = () => setIsResizingToolbar(false);
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [isResizingToolbar]);

  useEffect(() => {
    const shell = fullscreenShellRef.current;
    if (!shell || displayGraph.nodes.length === 0) return;
    const onChange = () => {
      setIsGraphFullscreen(isGraphShellFullscreen(shell));
      scheduleGraphResize(coreRef.current);
    };
    document.addEventListener("fullscreenchange", onChange);
    document.addEventListener("webkitfullscreenchange", onChange);
    setIsGraphFullscreen(isGraphShellFullscreen(shell));
    return () => {
      document.removeEventListener("fullscreenchange", onChange);
      document.removeEventListener("webkitfullscreenchange", onChange);
    };
  }, [displayGraph.nodes.length]);

  const handleToggleGraphFullscreen = () => {
    const shell = fullscreenShellRef.current;
    if (!shell) return;
    if (isGraphShellFullscreen(shell)) {
      void exitGraphFullscreen();
    } else {
      void requestGraphFullscreen(shell).catch(() => {});
    }
  };

  if (graph.nodes.length === 0) {
    return (
      <div className="sg-graph">
        <p className="sg-page__hint">
          Graph data is empty. Re-run the scan with task 0 (run all) to populate
          the graph, or this artifact may not contain any parseable structures.
        </p>
      </div>
    );
  }

  if (displayGraph.nodes.length === 0) {
    return (
      <div className="sg-graph">
        <p className="sg-page__hint">
          No nodes in the current view.
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
    if (selected.calls_custom_error) outgoingLabels.push("revert custom error");
    if (selected.calls_include_template)
      outgoingLabels.push("TU .c include template (heuristic)");
  }

  const explorationHints =
    "exploration_hints" in displayGraph ? displayGraph.exploration_hints : undefined;

  return (
    <div className="sg-graph">
      <div ref={fullscreenShellRef} className="sg-graph__fullscreen-shell">
      {!graphCanvasOnly && explorationHints && (
        <p className="sg-page__hint" style={{ margin: "0 16px 8px" }}>
          C graph (heuristic): {explorationHints.call_edge_count} edge(s); nodes{" "}
          {explorationHints.node_count ?? "?"}, edges {explorationHints.edge_count ?? "?"}.{" "}
          {explorationHints.large_graph_warning ? (
            <strong>{explorationHints.large_graph_note ?? "Large graph."} </strong>
          ) : null}
          {explorationHints.note ?? ""}
        </p>
      )}
      {!graphCanvasOnly && (
      <div
        ref={toolbarWrapRef}
        className="sg-graph__toolbar-wrap"
        style={{ maxHeight: `${toolbarPanelHeight}px` }}
      >
      <div className="sg-graph__toolbar">
        <div className="sg-graph__toolbar-top">
          <div className="sg-graph__metrics" aria-label="Graph summary">
            <span className="sg-graph__stat">
              {displayGraph.nodes.length} nodes / {displayGraph.edges.length} edges
              {interContractOnly ? " (inter-contract)" : ""}
            </span>
            <span className="sg-graph__stat">state-writers: {stateWritersCount}</span>
            <span className="sg-graph__stat">
              entrypoint-writers: {entrypointWritersCount}
            </span>
          </div>
          <div className="sg-graph__actions">
            <div className="sg-graph__action-group" role="group" aria-label="View mode">
              <button
                type="button"
                className="sg-button sg-button--ghost"
                onClick={() => {
                  setInterContractOnly((v) => !v);
                  setHighlightStateWrites(false);
                  setHighlightEntrypointWrites(false);
                  setFocusSelectionEnabled(false);
                }}
              >
                {interContractOnly ? "Full graph" : "Inter-contract"}
              </button>
              <button type="button" className="sg-button sg-button--ghost" onClick={handleFit}>
                Fit
              </button>
              <button
                type="button"
                className="sg-button sg-button--ghost"
                onClick={handleToggleGraphFullscreen}
                title={
                  isGraphFullscreen
                    ? "Exit fullscreen (Esc)"
                    : "Fullscreen: graph, toolbar, legend, and details panel"
                }
              >
                {isGraphFullscreen ? "Exit fullscreen" : "Fullscreen"}
              </button>
              <button
                type="button"
                className="sg-button sg-button--ghost"
                onClick={() => setGraphCanvasOnly(true)}
                title="Hide toolbar, legend, and details; show only the graph"
              >
                Graph only
              </button>
            </div>
            <div className="sg-graph__action-group" role="group" aria-label="Export">
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
            </div>
            <div className="sg-graph__action-group" role="group" aria-label="Highlights">
              <button
                type="button"
                className="sg-button sg-button--ghost"
                disabled={interContractOnly}
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
                disabled={interContractOnly}
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
            <div className="sg-graph__action-group" role="group" aria-label="Focus neighborhood">
              <button
                type="button"
                className="sg-button sg-button--ghost"
                disabled={interContractOnly || !focusEligible}
                aria-pressed={focusSelectionEnabled}
                title={
                  interContractOnly
                    ? "Not available in inter-contract view"
                    : !focusEligible
                      ? "Select a contract (type or tile node) first"
                      : "Temporarily show hidden nodes up to 2 hops away (shared hubs and peer contracts)"
                }
                onClick={() => setFocusSelectionEnabled((v) => !v)}
              >
                {focusSelectionEnabled ? "Clear focus" : "Focus selection"}
              </button>
            </div>
            <div className="sg-graph__action-group" role="group" aria-label="Extra edges">
              <button
                type="button"
                className="sg-button sg-button--ghost"
                onClick={() => setShowImports((v) => !v)}
              >
                {showImports ? "Hide imports" : "Show imports"}
              </button>
              <button
                type="button"
                className="sg-button sg-button--ghost"
                disabled={interContractOnly}
                title={
                  interContractOnly
                    ? "Links between contracts are always shown in Inter-contract view"
                    : "Show function-level cross-contract calls and external calls (contract extends stay in Inter-contract view)"
                }
                onClick={() => {
                  setShowCrossContractCalls((v) => {
                    const next = !v;
                    if (next) {
                      setHiddenLegend((prev) => {
                        if (!prev.edge_cross_type) {
                          return prev;
                        }
                        const copy = { ...prev };
                        delete copy.edge_cross_type;
                        return copy;
                      });
                    }
                    return next;
                  });
                }}
              >
                {showCrossContractCalls
                  ? "Hide cross-contract calls"
                  : "Show cross-contract calls"}
              </button>
            </div>
          </div>
        </div>
        <div className="sg-graph__toolbar-legends">
          <div className="sg-graph__legend-block">
            <span
              className="sg-graph__legend-heading"
              title="Click a label to hide or show that kind on the graph. Click again to restore."
            >
              Nodes
            </span>
            <div className="sg-graph__legend" role="group" aria-label="Node types visibility">
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--type${hiddenLegend.type_tile ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.type_tile)}
                onClick={() => toggleLegend("type_tile")}
              >
                type / tile
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--abstract-contract${hiddenLegend.abstract ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.abstract)}
                onClick={() => toggleLegend("abstract")}
              >
                abstract
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--interface-unit${hiddenLegend.interface ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.interface)}
                onClick={() => toggleLegend("interface")}
              >
                interface
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--library-unit${hiddenLegend.library ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.library)}
                onClick={() => toggleLegend("library")}
              >
                library
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--function${hiddenLegend.function ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.function)}
                onClick={() => toggleLegend("function")}
              >
                function
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--modifier-node${hiddenLegend.modifier ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.modifier)}
                onClick={() => toggleLegend("modifier")}
              >
                modifier
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--modifier${hiddenLegend.modifier_ring ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.modifier_ring)}
                onClick={() => toggleLegend("modifier_ring")}
              >
                modifier ring
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--state${hiddenLegend.state_workspace ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.state_workspace)}
                onClick={() => toggleLegend("state_workspace")}
              >
                state / workspace
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--event${hiddenLegend.event ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.event)}
                onClick={() => toggleLegend("event")}
              >
                event
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--custom-error${hiddenLegend.custom_error ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.custom_error)}
                onClick={() => toggleLegend("custom_error")}
              >
                error
              </button>
              <button
                type="button"
                className={`sg-graph__chip sg-graph__chip--external${hiddenLegend.external ? " sg-graph__chip--suppressed" : ""}`}
                aria-pressed={Boolean(hiddenLegend.external)}
                onClick={() => toggleLegend("external")}
              >
                external
              </button>
            </div>
          </div>
          <div className="sg-graph__legend-block">
            <span
              className="sg-graph__legend-heading"
              title="Click a filter to hide or show that edge family on the graph."
            >
              Edges
            </span>
            <p className="sg-graph__legend-hint">
              Arrow points from source node to target node.
            </p>
            <div className="sg-graph__edge-legend" role="group" aria-label="Edge kinds visibility">
              {EDGE_TOGGLE_ENTRIES.map((entry) => {
                const suppressed = Boolean(hiddenLegend[entry.bucket]);
                const classNames = [
                  "sg-graph__edge-key",
                  entry.className ?? "",
                  suppressed ? "sg-graph__edge-key--suppressed" : "",
                ]
                  .filter(Boolean)
                  .join(" ");
                return (
                  <button
                    key={entry.bucket}
                    type="button"
                    className={classNames}
                    style={entry.style}
                    aria-pressed={suppressed}
                    title={`Toggle ${entry.label} edges`}
                    onClick={() => toggleLegend(entry.bucket)}
                  >
                    {entry.label}
                  </button>
                );
              })}
            </div>
            <ul className="sg-graph__edge-legend-guide" aria-label="Edge meanings">
              {EDGE_GUIDE_ROWS.map((row) => (
                <li key={row.label} className="sg-graph__edge-legend-guide-row">
                  <span
                    className={[
                      "sg-graph__edge-legend-sample",
                      row.sampleClassName ?? "",
                    ]
                      .filter(Boolean)
                      .join(" ")}
                    style={row.sampleStyle}
                    aria-hidden
                  />
                  <span className="sg-graph__edge-legend-guide-text">
                    <strong>{row.label}</strong>
                    {" - "}
                    {row.description}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      </div>
      )}
      {!graphCanvasOnly && (
      <div
        className={`sg-graph__splitter sg-graph__splitter--row${isResizingToolbar ? " sg-graph__splitter--active" : ""}`}
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize maximum height of toolbar and legend panel"
        onMouseDown={(event) => {
          event.preventDefault();
          setIsResizingToolbar(true);
        }}
      />
      )}
      <div
        className={`sg-graph__workspace${graphCanvasOnly ? " sg-graph__workspace--graph-only" : ""}`}
        ref={workspaceRef}
        style={{ ["--sg-side-width" as string]: `${sidePanelWidth}px` }}
      >
        <div className="sg-graph__canvas-shell">
          {graphCanvasOnly ? (
            <button
              type="button"
              className="sg-button sg-button--ghost sg-graph__graph-only-exit"
              onClick={() => setGraphCanvasOnly(false)}
              title="Restore toolbar, legend, and details panel"
            >
              Show panels
            </button>
          ) : null}
          <div className="sg-graph__canvas" ref={containerRef} />
        </div>
        {!graphCanvasOnly ? (
          <>
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
                    <dt>
                      {selected.group === "state" || selected.group === "workspace"
                        ? "Contract"
                        : "Type"}
                    </dt>
                    <dd>{selected.type_name}</dd>
                  </>
                )}
                {selected.variable_type && (
                  <>
                    <dt>Type</dt>
                    <dd>{selected.variable_type}</dd>
                  </>
                )}
                {selected.storage_attributes && selected.storage_attributes.length > 0 && (
                  <>
                    <dt>Attributes</dt>
                    <dd>{selected.storage_attributes.join(", ")}</dd>
                  </>
                )}
                {selected.solidity_kind && (
                  <>
                    <dt>Solidity unit</dt>
                    <dd>
                      {selected.solidity_kind === "abstract"
                        ? "abstract contract"
                        : selected.solidity_kind}
                    </dd>
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
                {selected.group === "external_import" && selected.import_path && (
                  <>
                    <dt>Import path</dt>
                    <dd>{selected.import_path}</dd>
                  </>
                )}
                {selected.group === "external_import" && selected.resolution && (
                  <>
                    <dt>Resolution</dt>
                    <dd>{selected.resolution}</dd>
                  </>
                )}
                {selected.group === "external_import" &&
                  selectedExternalImportUsages.length > 0 && (
                  <>
                    <dt>Used from</dt>
                    <dd>
                      <ul className="sg-graph__modifiers">
                        {selectedExternalImportUsages.map((row) => (
                          <li
                            key={`${row.fromId}-${row.lines}`}
                            className="sg-graph__modifier-row"
                          >
                            <span>{row.fromLabel}</span>
                            {row.lines ? <span>{` (lines ${row.lines})`}</span> : null}
                            {row.callsite ? (
                              <pre className="sg-graph__code">
                                <code>{row.callsite}</code>
                              </pre>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
                {selected.source_file && (
                  <>
                    <dt>Source file</dt>
                    <dd>{selected.source_file}</dd>
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
                {selected.group === "function" && selectedImportUsages.length > 0 && (
                  <>
                    <dt>Import usage</dt>
                    <dd>
                      <ul className="sg-graph__modifiers">
                        {selectedImportUsages.map((row) => (
                          <li
                            key={`${row.symbol}-${row.lines}`}
                            className="sg-graph__modifier-row"
                          >
                            <span>{row.symbol}</span>
                            <span>{` -> ${row.targetLabel}`}</span>
                            {row.lines ? <span>{` (lines ${row.lines})`}</span> : null}
                            <span className="sg-page__hint">{row.path}</span>
                            {row.callsite ? (
                              <pre className="sg-graph__code">
                                <code>{row.callsite}</code>
                              </pre>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
                {selected.group === "function" &&
                  selected.heuristic_callees_ordered &&
                  selected.heuristic_callees_ordered.length > 0 && (
                  <>
                    <dt>Call order (heuristic)</dt>
                    <dd>{selected.heuristic_callees_ordered.join(" -> ")}</dd>
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
                {(selected.group === "state" || selected.group === "workspace") &&
                  (selected.kind === "state_variable" || selected.kind === "object_instance") &&
                  selected.source_body && (
                  <>
                    <dt>Declaration</dt>
                    <dd>
                      <pre className="sg-graph__code">
                        <code>{selected.source_body}</code>
                      </pre>
                    </dd>
                  </>
                )}
                {(selected.group === "state" || selected.group === "workspace") &&
                  stateReaderFunctionLabels.length > 0 && (
                  <>
                    <dt>Readers</dt>
                    <dd>
                      <ul className="sg-graph__modifiers">
                        {stateReaderFunctionLabels.map((name) => (
                          <li key={`read-${name}`} className="sg-graph__modifier-row">
                            <span>{name}</span>
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
                {(selected.group === "state" || selected.group === "workspace") &&
                  stateWriterFunctionLabels.length > 0 && (
                  <>
                    <dt>Writers</dt>
                    <dd>
                      <ul className="sg-graph__modifiers">
                        {stateWriterFunctionLabels.map((name) => (
                          <li key={`write-${name}`} className="sg-graph__modifier-row">
                            <span>{name}</span>
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
                {(selected.group === "state" || selected.group === "workspace") &&
                  selected.kind === "struct" &&
                  selected.source_body && (
                  <>
                    <dt>Struct fields</dt>
                    <dd>
                      <pre className="sg-graph__code">
                        <code>{selected.source_body}</code>
                      </pre>
                    </dd>
                  </>
                )}
                {(selected.group === "state" || selected.group === "workspace") &&
                  selected.kind === "include_template" &&
                  selected.source_body && (
                  <>
                    <dt>Include</dt>
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
                {selectedEdge.import_symbol && (
                  <>
                    <dt>Symbol</dt>
                    <dd>{selectedEdge.import_symbol}</dd>
                  </>
                )}
                {selectedEdge.kind === "import_dependency" &&
                  (selectedEdge.import_path || selectedEdge.label) && (
                  <>
                    <dt>Import path</dt>
                    <dd>{selectedEdge.import_path ?? selectedEdge.label}</dd>
                  </>
                )}
                {selectedEdge.resolution && (
                  <>
                    <dt>Resolution</dt>
                    <dd>{selectedEdge.resolution}</dd>
                  </>
                )}
                {selectedEdge.kind !== "import_dependency" && selectedEdge.label && (
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
          </>
        ) : null}
      </div>
      </div>
    </div>
  );
}
