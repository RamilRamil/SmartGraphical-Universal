import { useMemo, useState } from "react";
import type { ChangeEvent, DragEvent, FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { RunScanForm } from "../components/RunScanForm";
import { SgApiError } from "../api/client";
import { useUploadArtifactBundle, useUploadArtifactsBatch } from "../api/hooks";
import type { Artifact, BatchUploadResponse } from "../api/types";

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
const MAX_BATCH_FILES = 32;
const ALLOWED_EXTENSIONS = [".sol", ".c", ".h", ".rs"];

function detectLanguage(fileName: string): string | null {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".sol")) return "solidity";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".c") || lower.endsWith(".h")) return "c";
  return null;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatApiError(err: unknown): string {
  if (err instanceof SgApiError) return `${err.code}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

function validateFilesArray(
  files: File[],
  layout: "separate" | "combined",
): { ok: true; files: File[] } | { ok: false; error: string } {
  if (files.length === 0) {
    return { ok: false, error: "No files selected." };
  }
  if (files.length > MAX_BATCH_FILES) {
    return { ok: false, error: `At most ${MAX_BATCH_FILES} files per batch.` };
  }
  for (const f of files) {
    if (f.size === 0) {
      return { ok: false, error: `${f.name} is empty.` };
    }
    if (f.size > MAX_UPLOAD_BYTES) {
      return { ok: false, error: `${f.name} exceeds ${formatSize(MAX_UPLOAD_BYTES)}.` };
    }
    const allowed = ALLOWED_EXTENSIONS.some((ext) => f.name.toLowerCase().endsWith(ext));
    if (!allowed) {
      return {
        ok: false,
        error: `${f.name}: unsupported extension. Allowed: ${ALLOWED_EXTENSIONS.join(", ")}.`,
      };
    }
  }
  if (layout === "combined") {
    const langs = new Set<string>();
    for (const f of files) {
      const d = detectLanguage(f.name);
      if (d) langs.add(d);
    }
    if (langs.size > 1) {
      return {
        ok: false,
        error: "Combined upload requires files in a single language.",
      };
    }
  }
  return { ok: true, files };
}

function validateFileList(
  list: FileList | null,
  layout: "separate" | "combined",
): { ok: true; files: File[] } | { ok: false; error: string } {
  if (!list || list.length === 0) {
    return { ok: false, error: "No files selected." };
  }
  return validateFilesArray(Array.from(list), layout);
}

export function UploadPage() {
  const navigate = useNavigate();
  const [uploadLayout, setUploadLayout] = useState<"separate" | "combined">("separate");
  const [pendingFiles, setPendingFiles] = useState<File[]>([]);
  const [clientError, setClientError] = useState<string | null>(null);
  const [batchResult, setBatchResult] = useState<BatchUploadResponse | null>(null);
  const [bundleArtifact, setBundleArtifact] = useState<Artifact | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const batchMutation = useUploadArtifactsBatch();
  const bundleMutation = useUploadArtifactBundle();

  const previewLanguages = useMemo(() => {
    const langs = new Set<string>();
    for (const f of pendingFiles) {
      const d = detectLanguage(f.name);
      if (d) langs.add(d);
    }
    return Array.from(langs).sort().join(", ") || "unknown";
  }, [pendingFiles]);

  function applyFileList(list: FileList | null) {
    setClientError(null);
    setBatchResult(null);
    setBundleArtifact(null);
    const result = validateFileList(list, uploadLayout);
    if (!result.ok) {
      setClientError(result.error);
      setPendingFiles([]);
      return;
    }
    setPendingFiles(result.files);
  }

  function handleLayoutChange(next: "separate" | "combined") {
    setUploadLayout(next);
    setClientError(null);
    setBatchResult(null);
    setBundleArtifact(null);
    batchMutation.reset();
    bundleMutation.reset();
    if (pendingFiles.length === 0) return;
    const v = validateFilesArray(pendingFiles, next);
    if (!v.ok) {
      setClientError(v.error);
      setPendingFiles([]);
    }
  }

  function handleFileInput(event: ChangeEvent<HTMLInputElement>) {
    applyFileList(event.target.files);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragOver(false);
    applyFileList(event.dataTransfer.files);
  }

  function handleDragOver(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragOver(true);
  }

  function handleDragLeave(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragOver(false);
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pendingFiles.length === 0) return;
    try {
      if (uploadLayout === "combined") {
        const art = await bundleMutation.mutateAsync(pendingFiles);
        setBundleArtifact(art);
      } else {
        const data = await batchMutation.mutateAsync(pendingFiles);
        setBatchResult(data);
      }
    } catch {
      // surfaced via mutation.error
    }
  }

  const uploadError =
    batchMutation.error || bundleMutation.error ? formatApiError(batchMutation.error || bundleMutation.error) : null;

  const singleSuccessArtifact: Artifact | null = useMemo(() => {
    if (!batchResult) return null;
    if (batchResult.summary.ok !== 1 || batchResult.summary.error !== 0) return null;
    const okRows = batchResult.items.filter((x): x is { ok: true; artifact: Artifact } => x.ok);
    if (okRows.length !== 1) return null;
    const only = okRows[0];
    return only ? only.artifact : null;
  }, [batchResult]);

  const resultSuccesses = useMemo(() => {
    if (!batchResult) return [];
    return batchResult.items.filter((x) => x.ok) as Array<{ ok: true; artifact: Artifact }>;
  }, [batchResult]);

  const resultFailures = useMemo(() => {
    if (!batchResult) return [];
    return batchResult.items.filter((x) => !x.ok) as Array<{
      ok: false;
      filename: string;
      code: string;
      message: string;
    }>;
  }, [batchResult]);

  function resetFlow() {
    setBatchResult(null);
    setBundleArtifact(null);
    setPendingFiles([]);
    setClientError(null);
    batchMutation.reset();
    bundleMutation.reset();
  }

  const showForm = !batchResult && !bundleArtifact;
  const uploadPending = batchMutation.isPending || bundleMutation.isPending;

  return (
    <section className="sg-page">
      <h1 className="sg-page__title">Upload artifacts</h1>

      {showForm && (
        <form className="sg-form" onSubmit={handleUpload}>
          <fieldset className="sg-form__fieldset" style={{ border: "none", padding: 0, margin: "0 0 1rem" }}>
            <legend className="sg-form__hint" style={{ marginBottom: "0.5rem" }}>
              Upload mode
            </legend>
            <label style={{ marginRight: "1.25rem" }}>
              <input
                type="radio"
                name="uploadLayout"
                checked={uploadLayout === "separate"}
                onChange={() => handleLayoutChange("separate")}
              />{" "}
              Separate artifacts (one scan target per file)
            </label>
            <label>
              <input
                type="radio"
                name="uploadLayout"
                checked={uploadLayout === "combined"}
                onChange={() => handleLayoutChange("combined")}
              />{" "}
              Combined graph (one artifact; graph merges all files in one language)
            </label>
          </fieldset>

          <div
            className={`sg-dropzone${isDragOver ? " sg-dropzone--active" : ""}`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <p className="sg-dropzone__label">
              {uploadLayout === "combined"
                ? "Drop or select multiple files for one bundle. C: .c/.h includes; Solidity: import of other .sol in the bundle; Rust: mod / use crate:: / use super:: to other .rs. Union graph plus these links."
                : "Drag and drop source files here, or select them (multiple allowed). Each file becomes a separate artifact."}
            </p>
            <input
              type="file"
              accept=".sol,.c,.h,.rs"
              multiple
              onChange={handleFileInput}
              aria-label="Source files"
            />
            <p className="sg-form__hint">
              Max {MAX_BATCH_FILES} files; {formatSize(MAX_UPLOAD_BYTES)} per file.
              Allowed: {ALLOWED_EXTENSIONS.join(", ")}.
            </p>
          </div>

          {clientError && <p className="sg-banner sg-banner--error">{clientError}</p>}

          {pendingFiles.length > 0 && (
            <div className="sg-preview">
              <div>
                <span className="sg-preview__label">Files</span>
                <span className="sg-preview__value">{pendingFiles.length} selected</span>
              </div>
              <ul className="sg-form__hint" style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
                {pendingFiles.map((f) => (
                  <li key={`${f.name}-${f.size}-${f.lastModified}`}>
                    {f.name} ({formatSize(f.size)})
                  </li>
                ))}
              </ul>
              <div>
                <span className="sg-preview__label">Languages (detected)</span>
                <span className="sg-preview__value">{previewLanguages}</span>
              </div>
            </div>
          )}

          {uploadError && <p className="sg-banner sg-banner--error">Upload failed: {uploadError}</p>}

          <button
            type="submit"
            className="sg-button sg-button--primary"
            disabled={pendingFiles.length === 0 || uploadPending}
          >
            {uploadPending
              ? "Uploading..."
              : pendingFiles.length <= 1
                ? "Upload"
                : `Upload ${pendingFiles.length} files`}
          </button>
        </form>
      )}

      {bundleArtifact && (
        <div className="sg-form">
          <p className="sg-form__hint">
            Combined artifact created. Findings are merged; the graph unions per-file models and adds explicit links for C includes, Solidity imports, and Rust module references when they point at other files in the bundle.
          </p>
          <p>
            <Link className="sg-link" to={`/artifacts/${bundleArtifact.id}`}>
              #{bundleArtifact.id} {bundleArtifact.filename}
            </Link>{" "}
            ({bundleArtifact.language})
          </p>
          <RunScanForm
            artifactId={bundleArtifact.id}
            language={bundleArtifact.language}
            onSuccess={(scan) => navigate(`/scans/${scan.id}`)}
          />
          <div className="sg-form__actions">
            <button type="button" className="sg-button" onClick={resetFlow}>
              Upload more files
            </button>
            <Link to="/history" className="sg-button sg-button--ghost">
              History
            </Link>
          </div>
        </div>
      )}

      {batchResult && (
        <div className="sg-form">
          <p className="sg-form__hint">
            Uploaded {batchResult.summary.ok} ok, {batchResult.summary.error} failed.
          </p>

          {resultSuccesses.length > 0 && (
            <div className="sg-preview">
              <span className="sg-preview__label">Artifacts</span>
              <ul className="sg-form__hint" style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
                {resultSuccesses.map((row) => (
                  <li key={`${row.artifact.id}-${row.artifact.filename}`}>
                    <Link to={`/artifacts/${row.artifact.id}`}>
                      #{row.artifact.id} {row.artifact.filename}
                    </Link>{" "}
                    ({row.artifact.language})
                  </li>
                ))}
              </ul>
            </div>
          )}

          {resultFailures.length > 0 && (
            <div className="sg-banner sg-banner--error">
              <strong>Failed</strong>
              <ul style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
                {resultFailures.map((row) => (
                  <li key={row.filename}>
                    {row.filename}: {row.code} — {row.message}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {singleSuccessArtifact && (
            <RunScanForm
              artifactId={singleSuccessArtifact.id}
              language={singleSuccessArtifact.language}
              onSuccess={(scan) => navigate(`/scans/${scan.id}`)}
            />
          )}

          <div className="sg-form__actions">
            <button type="button" className="sg-button" onClick={resetFlow}>
              Upload more files
            </button>
            <Link to="/history" className="sg-button sg-button--ghost">
              History
            </Link>
          </div>
        </div>
      )}
    </section>
  );
}
