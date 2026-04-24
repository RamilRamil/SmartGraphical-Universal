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
  group: "type" | "function" | "state" | "event" | "modifier" | "external";
  parent?: string;
  kind?: string;
  type_name?: string;
  modifier_color?: string;
  visibility?: string;
  is_entrypoint?: boolean;
  source_body?: string;
  modifier_details?: ModifierSwatch[];
  modifier_ring_details?: ModifierSwatch[];
  calls_internal?: boolean;
  calls_contract?: boolean;
  calls_system?: boolean;
  calls_event?: boolean;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  kind: string;
  label: string;
};

export type GraphData = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

export type GraphPayload = {
  status: string;
  artifact: {
    path: string;
    language: string;
    adapter_name: string;
  } | null;
  language: string;
  duration_ms: number;
  model_summary: {
    artifact: { path: string; language: string; adapter_name: string } | null;
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
