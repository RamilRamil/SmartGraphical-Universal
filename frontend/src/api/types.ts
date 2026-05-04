export type HealthResponse = {
  status: string;
  service: string;
  supported_languages: string[];
  supported_modes: string[];
};

export type Artifact = {
  id: number;
  sha256: string;
  filename: string;
  language: string;
  size_bytes: number;
  path_on_disk: string;
  created_at: string;
};

export type BatchArtifactItem =
  | { ok: true; artifact: Artifact }
  | { ok: false; filename: string; code: string; message: string };

export type BatchUploadResponse = {
  items: BatchArtifactItem[];
  summary: { ok: number; error: number };
};

export type Scan = {
  id: number;
  artifact_id: number;
  mode: string;
  task: string;
  rules_run_json: string;
  findings_count: number;
  duration_ms: number;
  tool_version: string;
  rules_catalog_hash: string;
  findings_payload_path: string;
  graph_payload_path: string;
  status: string;
  error_code: string;
  error_message: string;
  created_at: string;
  deleted_at: string | null;
};

export type Evidence = {
  kind: string;
  summary: string;
  type_name: string;
  function_name: string;
  statement: string;
  source_statement: string;
  confidence_reason: string;
  line_number?: number;
  line_numbers?: number[];
};

export type Finding = {
  task_id: string;
  legacy_code: number;
  rule_id: string;
  title: string;
  category: string;
  portability: string;
  confidence: string;
  message: string;
  remediation_hint: string;
  evidences: Evidence[];
  source_file?: string;
};

export type ScanDetail = {
  scan: Scan;
  artifact: Artifact | null;
  findings: Finding[];
};

export type ModifierSwatch = {
  name: string;
  color: string;
};

export type GraphNode = {
  id: string;
  label: string;
  group:
    | "type"
    | "tile"
    | "function"
    | "state"
    | "workspace"
    | "event"
    | "modifier"
    | "external"
    | "modifier_ring";
  parent?: string;
  kind?: string;
  type_name?: string;
  modifier_color?: string;
  visibility?: string;
  is_entrypoint?: boolean;
  source_body?: string;
  full_source?: string;
  modifier_details?: ModifierSwatch[];
  modifier_ring_details?: ModifierSwatch[];
  calls_internal?: boolean;
  calls_contract?: boolean;
  calls_system?: boolean;
  calls_event?: boolean;
  calls_include_template?: boolean;
  heuristic_callees_ordered?: string[];
  state_reads?: string[];
  state_writes?: string[];
  guards?: string[];
  write_paths?: Array<{ path: string; confidence: string }>;
  source_file?: string;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  kind: string;
  label: string;
  callsite?: string;
  args_map?: Array<{ param: string; value: string; source_kind?: string }>;
  line_numbers?: number[];
};

export type GraphExplorationHints = {
  call_edges_are_heuristic: boolean;
  call_edge_count: number;
  node_count?: number;
  edge_count?: number;
  large_graph_warning?: boolean;
  large_graph_note?: string;
  note?: string;
};

export type GraphData = {
  graph_schema_version?: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  exploration_hints?: GraphExplorationHints;
};

export type GraphPayload = {
  status: string;
  artifact: string | { path: string; language: string; adapter_name: string } | null;
  language: string;
  duration_ms: number;
  model_summary: {
    artifact: {
      path: string;
      language: string;
      adapter_name: string;
      bundle_members?: string[];
    } | null;
    types_count: number;
    functions_count: number;
    state_entities_count: number;
    guards_count: number;
    call_edges_count: number;
    graph?: GraphData;
  };
};

export type GraphResponse =
  | { available: false }
  | { available: true; graph: GraphPayload };

export type DiffResponse = {
  scan_a_id: number;
  scan_b_id: number;
  artifact_id: number;
  added: Finding[];
  removed: Finding[];
  unchanged_count: number;
};

export type ApiError = {
  status: "error";
  code: string;
  message: string;
};

export type RunScanRequest = {
  task: string;
  mode?: string;
};

export type TaskDescriptor = {
  id: string;
  title: string;
  category: string;
  portability: string;
  confidence: string;
  kind: "rule" | "meta";
};

export type TaskList = {
  language: string;
  tasks: TaskDescriptor[];
  count: number;
};
