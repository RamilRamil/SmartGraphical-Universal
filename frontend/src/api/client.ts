import type {
  ApiError,
  Artifact,
  BatchUploadResponse,
  DiffResponse,
  Finding,
  GraphResponse,
  HealthResponse,
  RunScanRequest,
  Scan,
  ScanDetail,
  TaskList,
} from "./types";

const API_BASE = "/api";

export class SgApiError extends Error {
  public readonly code: string;
  public readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
    this.name = "SgApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const contentType = response.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    if (isJson && payload && typeof payload === "object" && "code" in payload) {
      const errorPayload = payload as ApiError;
      throw new SgApiError(errorPayload.code, errorPayload.message, response.status);
    }
    throw new SgApiError(
      "http_error",
      typeof payload === "string" ? payload : response.statusText,
      response.status,
    );
  }

  return payload as T;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export const api = {
  health: () => request<HealthResponse>("/health"),
  listTasks: (language: string) =>
    request<TaskList>(`/languages/${encodeURIComponent(language)}/tasks`),
  listArtifacts: (limit = 50) =>
    request<{ items: Artifact[] }>(`/artifacts?limit=${limit}`),
  getArtifact: (artifactId: number) => request<Artifact>(`/artifacts/${artifactId}`),
  uploadArtifact: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return request<Artifact>("/artifacts", {
      method: "POST",
      body: formData,
    });
  },
  uploadArtifactsBatch: (files: File[]) => {
    const formData = new FormData();
    for (const f of files) {
      formData.append("files", f);
    }
    return request<BatchUploadResponse>("/artifacts/batch", {
      method: "POST",
      body: formData,
    });
  },
  uploadArtifactBundle: (files: File[]) => {
    const formData = new FormData();
    for (const f of files) {
      formData.append("files", f);
    }
    return request<Artifact>("/artifacts/bundle", {
      method: "POST",
      body: formData,
    });
  },
  listScans: (artifactId: number | null = null, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (artifactId !== null) {
      params.set("artifact_id", String(artifactId));
    }
    return request<{ items: Scan[] }>(`/scans?${params.toString()}`);
  },
  getScan: (scanId: number) => request<ScanDetail>(`/scans/${scanId}`),
  getFindings: (scanId: number) =>
    request<{ items: Finding[] }>(`/scans/${scanId}/findings`),
  getGraph: (scanId: number) => request<GraphResponse>(`/scans/${scanId}/graph`),
  diffScans: (scanA: number, scanB: number) =>
    request<DiffResponse>(`/scans/${scanA}/diff/${scanB}`),
  createScan: (artifactId: number, body: RunScanRequest) =>
    postJson<Scan>(`/artifacts/${artifactId}/scans`, body),
  deleteScan: (scanId: number) =>
    request<{ deleted: boolean; scan_id: number }>(`/scans/${scanId}`, {
      method: "DELETE",
    }),
};
