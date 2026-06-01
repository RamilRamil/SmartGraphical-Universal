import type {
  CallFlowDepthMode,
  CallFlowDirection,
} from "./buildCallFlowSubgraph";

export const CALL_FLOW_PREFS_STORAGE_KEY = "smartgraphical.callFlow.prefs";

export type CallFlowSessionPrefs = {
  direction: CallFlowDirection;
  depth: number;
  depthMode: CallFlowDepthMode;
  showExternalCalls: boolean;
};

const DEFAULT_PREFS: CallFlowSessionPrefs = {
  direction: "both",
  depth: 2,
  depthMode: "limited",
  showExternalCalls: true,
};

function isDirection(value: unknown): value is CallFlowDirection {
  return value === "upstream" || value === "both" || value === "downstream";
}

function isDepthMode(value: unknown): value is CallFlowDepthMode {
  return value === "limited" || value === "full";
}

export function parseCallFlowSessionPrefs(raw: string | null): CallFlowSessionPrefs | null {
  if (!raw) return null;
  try {
    const data = JSON.parse(raw) as Record<string, unknown> | null;
    if (!data || typeof data !== "object") return null;
    if (!isDirection(data.direction)) return null;
    if (!isDepthMode(data.depthMode)) return null;
    const depth = data.depth;
    if (typeof depth !== "number" || !Number.isInteger(depth) || depth < 1 || depth > 4) {
      return null;
    }
    if (typeof data.showExternalCalls !== "boolean") return null;
    return {
      direction: data.direction,
      depth,
      depthMode: data.depthMode,
      showExternalCalls: data.showExternalCalls,
    };
  } catch {
    return null;
  }
}

export function defaultCallFlowSessionPrefs(): CallFlowSessionPrefs {
  return { ...DEFAULT_PREFS };
}

export function loadCallFlowSessionPrefs(): CallFlowSessionPrefs {
  if (typeof sessionStorage === "undefined") {
    return defaultCallFlowSessionPrefs();
  }
  try {
    const raw = sessionStorage.getItem(CALL_FLOW_PREFS_STORAGE_KEY);
    return parseCallFlowSessionPrefs(raw) ?? defaultCallFlowSessionPrefs();
  } catch {
    return defaultCallFlowSessionPrefs();
  }
}

export function saveCallFlowSessionPrefs(prefs: CallFlowSessionPrefs): void {
  if (typeof sessionStorage === "undefined") return;
  try {
    sessionStorage.setItem(CALL_FLOW_PREFS_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    /* quota / private mode */
  }
}
