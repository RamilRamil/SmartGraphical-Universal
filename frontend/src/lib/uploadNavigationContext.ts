const STORAGE_KEY = "sg.upload.context";

export type UploadLayoutMode = "separate" | "combined";

type StoredPayload = {
  artifactId: number;
  layout: UploadLayoutMode;
};

export function parseUploadLayoutParam(raw: string | null): UploadLayoutMode | null {
  const v = (raw || "").trim().toLowerCase();
  if (v === "separate" || v === "combined") return v;
  return null;
}

export function saveUploadContextForScan(artifactId: number, layout: UploadLayoutMode): void {
  try {
    const payload: StoredPayload = { artifactId, layout };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  } catch {
    /* quota / private mode */
  }
}

/**
 * Returns layout used when the scan was started from Upload for this artifact, if recorded.
 */
export function getUploadLayoutForArtifact(artifactId: number): UploadLayoutMode | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const data = JSON.parse(raw) as StoredPayload | null;
    if (!data || typeof data.artifactId !== "number" || data.artifactId !== artifactId) {
      return null;
    }
    if (data.layout === "separate" || data.layout === "combined") return data.layout;
    return null;
  } catch {
    return null;
  }
}
