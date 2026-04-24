import { useMemo, useState } from "react";
import type { ChangeEvent, DragEvent, FormEvent } from "react";
import { useNavigate } from "react-router-dom";

import { RunScanForm } from "../components/RunScanForm";
import { SgApiError } from "../api/client";
import { useUploadArtifact } from "../api/hooks";
import type { Artifact } from "../api/types";

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".sol", ".c", ".h"];

function detectLanguage(fileName: string): string | null {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".sol")) return "solidity";
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

export function UploadPage() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [clientError, setClientError] = useState<string | null>(null);
  const [uploaded, setUploaded] = useState<Artifact | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const uploadMutation = useUploadArtifact();

  const detectedLanguage = useMemo(
    () => (file ? detectLanguage(file.name) : null),
    [file],
  );

  function validateAndSetFile(next: File | null) {
    setClientError(null);
    setUploaded(null);
    if (!next) {
      setFile(null);
      return;
    }
    if (next.size === 0) {
      setClientError("File is empty.");
      setFile(null);
      return;
    }
    if (next.size > MAX_UPLOAD_BYTES) {
      setClientError(`File exceeds ${MAX_UPLOAD_BYTES} bytes.`);
      setFile(null);
      return;
    }
    const hasAllowedExt = ALLOWED_EXTENSIONS.some((ext) =>
      next.name.toLowerCase().endsWith(ext),
    );
    if (!hasAllowedExt) {
      setClientError(
        `Unsupported extension. Allowed: ${ALLOWED_EXTENSIONS.join(", ")}.`,
      );
      setFile(null);
      return;
    }
    setFile(next);
  }

  function handleFileInput(event: ChangeEvent<HTMLInputElement>) {
    const next = event.target.files && event.target.files[0];
    validateAndSetFile(next ?? null);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragOver(false);
    const next = event.dataTransfer.files && event.dataTransfer.files[0];
    validateAndSetFile(next ?? null);
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
    if (!file) return;
    try {
      const artifact = await uploadMutation.mutateAsync(file);
      setUploaded(artifact);
    } catch {
      // surfaced via uploadMutation.error
    }
  }

  const uploadError = uploadMutation.error
    ? formatApiError(uploadMutation.error)
    : null;

  return (
    <section className="sg-page">
      <h1 className="sg-page__title">Upload artifact</h1>

      {!uploaded && (
        <form className="sg-form" onSubmit={handleUpload}>
          <div
            className={`sg-dropzone${isDragOver ? " sg-dropzone--active" : ""}`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <p className="sg-dropzone__label">
              Drag and drop a source file here, or select it manually.
            </p>
            <input
              type="file"
              accept=".sol,.c,.h"
              onChange={handleFileInput}
              aria-label="Source file"
            />
            <p className="sg-form__hint">
              Limit {formatSize(MAX_UPLOAD_BYTES)}. Allowed:{" "}
              {ALLOWED_EXTENSIONS.join(", ")}.
            </p>
          </div>

          {clientError && <p className="sg-banner sg-banner--error">{clientError}</p>}

          {file && (
            <div className="sg-preview">
              <div>
                <span className="sg-preview__label">File</span>
                <span className="sg-preview__value">{file.name}</span>
              </div>
              <div>
                <span className="sg-preview__label">Size</span>
                <span className="sg-preview__value">{formatSize(file.size)}</span>
              </div>
              <div>
                <span className="sg-preview__label">Detected language</span>
                <span className="sg-preview__value">
                  {detectedLanguage ?? "unknown"}
                </span>
              </div>
            </div>
          )}

          {uploadError && (
            <p className="sg-banner sg-banner--error">Upload failed: {uploadError}</p>
          )}

          <button
            type="submit"
            className="sg-button sg-button--primary"
            disabled={!file || uploadMutation.isPending}
          >
            {uploadMutation.isPending ? "Uploading..." : "Upload"}
          </button>
        </form>
      )}

      {uploaded && (
        <div className="sg-form">
          <div className="sg-preview">
            <div>
              <span className="sg-preview__label">Artifact</span>
              <span className="sg-preview__value">
                #{uploaded.id} {uploaded.filename}
              </span>
            </div>
            <div>
              <span className="sg-preview__label">Language</span>
              <span className="sg-preview__value">{uploaded.language}</span>
            </div>
            <div>
              <span className="sg-preview__label">SHA256</span>
              <span className="sg-preview__value sg-preview__value--mono">
                {uploaded.sha256.slice(0, 16)}...
              </span>
            </div>
          </div>

          <RunScanForm
            artifactId={uploaded.id}
            language={uploaded.language}
            onSuccess={(scan) => navigate(`/scans/${scan.id}`)}
          />

          <div className="sg-form__actions">
            <button
              type="button"
              className="sg-button"
              onClick={() => {
                setUploaded(null);
                setFile(null);
                uploadMutation.reset();
              }}
            >
              Upload another file
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
