import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseQueryOptions } from "@tanstack/react-query";

import { api } from "./client";
import type { Artifact, BatchUploadResponse, RunScanRequest, Scan } from "./types";

export const queryKeys = {
  health: ["health"] as const,
  tasks: (language: string) => ["tasks", language] as const,
  artifacts: ["artifacts"] as const,
  artifact: (id: number) => ["artifact", id] as const,
  scans: (artifactId: number | null) => ["scans", artifactId] as const,
  scan: (id: number) => ["scan", id] as const,
  findings: (id: number) => ["findings", id] as const,
  graph: (id: number) => ["graph", id] as const,
  diff: (a: number, b: number) => ["diff", a, b] as const,
};

export function useHealth(options?: Partial<UseQueryOptions<Awaited<ReturnType<typeof api.health>>>>) {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: () => api.health(),
    staleTime: 30_000,
    ...options,
  });
}

export function useTasks(language: string | undefined) {
  return useQuery({
    queryKey: language ? queryKeys.tasks(language) : ["tasks", "disabled"],
    queryFn: () => {
      if (!language) {
        throw new Error("language is required");
      }
      return api.listTasks(language);
    },
    enabled: Boolean(language),
    staleTime: 5 * 60_000,
  });
}

export function useArtifacts() {
  return useQuery({
    queryKey: queryKeys.artifacts,
    queryFn: () => api.listArtifacts(),
  });
}

export function useArtifact(artifactId: number | undefined) {
  return useQuery({
    queryKey: artifactId !== undefined ? queryKeys.artifact(artifactId) : ["artifact", "disabled"],
    queryFn: () => {
      if (artifactId === undefined) {
        throw new Error("artifactId is required");
      }
      return api.getArtifact(artifactId);
    },
    enabled: artifactId !== undefined,
  });
}

export function useScans(artifactId: number | null = null) {
  return useQuery({
    queryKey: queryKeys.scans(artifactId),
    queryFn: () => api.listScans(artifactId),
  });
}

export function useScan(scanId: number | undefined) {
  return useQuery({
    queryKey: scanId !== undefined ? queryKeys.scan(scanId) : ["scan", "disabled"],
    queryFn: () => {
      if (scanId === undefined) {
        throw new Error("scanId is required");
      }
      return api.getScan(scanId);
    },
    enabled: scanId !== undefined,
  });
}

export function useDiff(scanA: number | undefined, scanB: number | undefined) {
  const canRun = scanA !== undefined && scanB !== undefined;
  return useQuery({
    queryKey: canRun
      ? queryKeys.diff(scanA as number, scanB as number)
      : ["diff", "disabled"],
    queryFn: () => {
      if (scanA === undefined || scanB === undefined) {
        throw new Error("both scan ids are required");
      }
      return api.diffScans(scanA, scanB);
    },
    enabled: canRun,
  });
}

export function useGraph(scanId: number | undefined) {
  return useQuery({
    queryKey: scanId !== undefined ? queryKeys.graph(scanId) : ["graph", "disabled"],
    queryFn: () => {
      if (scanId === undefined) {
        throw new Error("scanId is required");
      }
      return api.getGraph(scanId);
    },
    enabled: scanId !== undefined,
  });
}

export function useUploadArtifact() {
  const queryClient = useQueryClient();
  return useMutation<Artifact, Error, File>({
    mutationFn: (file: File) => api.uploadArtifact(file),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.artifacts });
    },
  });
}

export function useUploadArtifactsBatch() {
  const queryClient = useQueryClient();
  return useMutation<BatchUploadResponse, Error, File[]>({
    mutationFn: (files: File[]) => api.uploadArtifactsBatch(files),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.artifacts });
    },
  });
}

export function useUploadArtifactBundle() {
  const queryClient = useQueryClient();
  return useMutation<Artifact, Error, File[]>({
    mutationFn: (files: File[]) => api.uploadArtifactBundle(files),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.artifacts });
    },
  });
}

export function useCreateScan(artifactId: number) {
  const queryClient = useQueryClient();
  return useMutation<Scan, Error, RunScanRequest>({
    mutationFn: (body: RunScanRequest) => api.createScan(artifactId, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.scans(artifactId) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.scans(null) });
    },
  });
}

export function useDeleteScan() {
  const queryClient = useQueryClient();
  return useMutation<{ deleted: boolean; scan_id: number }, Error, number>({
    mutationFn: (scanId: number) => api.deleteScan(scanId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}
