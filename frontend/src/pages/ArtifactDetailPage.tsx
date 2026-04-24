import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { SgApiError } from "../api/client";
import {
  useArtifact,
  useDeleteScan,
  useScans,
} from "../api/hooks";
import { ConfirmModal } from "../components/ConfirmModal";
import { RunScanForm } from "../components/RunScanForm";
import { ScansTable } from "../components/ScansTable";
import type { Scan } from "../api/types";

function formatApiError(err: unknown): string {
  if (err instanceof SgApiError) return `${err.code}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function ArtifactDetailPage() {
  const { artifactId } = useParams<{ artifactId: string }>();
  const parsed = artifactId ? Number.parseInt(artifactId, 10) : undefined;
  const artifactQuery = useArtifact(
    Number.isFinite(parsed) ? (parsed as number) : undefined,
  );
  const scansQuery = useScans(
    Number.isFinite(parsed) ? (parsed as number) : null,
  );
  const deleteScan = useDeleteScan();
  const navigate = useNavigate();

  const [pendingDelete, setPendingDelete] = useState<Scan | null>(null);
  const [scanAId, setScanAId] = useState<string>("");
  const [scanBId, setScanBId] = useState<string>("");

  const scans = useMemo(
    () =>
      (scansQuery.data?.items ?? []).filter((scan) => !scan.deleted_at),
    [scansQuery.data],
  );

  if (!parsed || Number.isNaN(parsed)) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Artifact</h1>
        <p className="sg-banner sg-banner--error">Invalid artifact id.</p>
      </section>
    );
  }

  if (artifactQuery.isPending) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Artifact #{parsed}</h1>
        <p className="sg-page__hint">Loading...</p>
      </section>
    );
  }

  if (artifactQuery.error) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Artifact #{parsed}</h1>
        <p className="sg-banner sg-banner--error">
          Failed to load artifact: {formatApiError(artifactQuery.error)}
        </p>
      </section>
    );
  }

  const artifact = artifactQuery.data;
  if (!artifact) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Artifact #{parsed}</h1>
        <p className="sg-banner sg-banner--error">Artifact not found.</p>
      </section>
    );
  }

  const canCompare =
    scanAId !== "" && scanBId !== "" && scanAId !== scanBId;

  function handleCompare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canCompare) return;
    navigate(`/scans/${scanAId}/diff/${scanBId}`);
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    try {
      await deleteScan.mutateAsync(pendingDelete.id);
      setPendingDelete(null);
    } catch {
      // surfaced via deleteScan.error
    }
  }

  const deleteError = deleteScan.error ? formatApiError(deleteScan.error) : null;

  return (
    <section className="sg-page">
      <div className="sg-page__header">
        <h1 className="sg-page__title">
          Artifact #{artifact.id} {artifact.filename}
        </h1>
        <Link
          to={`/history?artifact_id=${artifact.id}`}
          className="sg-link"
        >
          Open in history
        </Link>
      </div>

      <div className="sg-meta">
        <div>
          <span className="sg-meta__label">Language</span>
          <span className="sg-meta__value">{artifact.language}</span>
        </div>
        <div>
          <span className="sg-meta__label">Size</span>
          <span className="sg-meta__value">{formatSize(artifact.size_bytes)}</span>
        </div>
        <div>
          <span className="sg-meta__label">Created</span>
          <span className="sg-meta__value">{artifact.created_at}</span>
        </div>
        <div>
          <span className="sg-meta__label">SHA256</span>
          <span className="sg-meta__value sg-meta__value--mono">
            {artifact.sha256}
          </span>
        </div>
      </div>

      <h2 className="sg-section__title">Run new scan</h2>
      <RunScanForm
        artifactId={artifact.id}
        language={artifact.language}
        onSuccess={(scan) => navigate(`/scans/${scan.id}`)}
      />

      <h2 className="sg-section__title">Scans</h2>
      <ScansTable
        scans={scans}
        isPending={scansQuery.isPending}
        errorMessage={
          scansQuery.error ? formatApiError(scansQuery.error) : null
        }
        emptyMessage="No scans for this artifact yet."
        onDelete={(scan) => {
          deleteScan.reset();
          setPendingDelete(scan);
        }}
      />

      {scans.length >= 2 && (
        <>
          <h2 className="sg-section__title">Compare two scans</h2>
          <form className="sg-form sg-form--row" onSubmit={handleCompare}>
            <label className="sg-field">
              <span className="sg-field__label">Scan A</span>
              <select
                className="sg-field__control"
                value={scanAId}
                onChange={(event) => setScanAId(event.target.value)}
              >
                <option value="" disabled>
                  Select scan
                </option>
                {scans.map((scan) => (
                  <option key={scan.id} value={String(scan.id)}>
                    #{scan.id} - task {scan.task} ({scan.findings_count} findings)
                  </option>
                ))}
              </select>
            </label>
            <label className="sg-field">
              <span className="sg-field__label">Scan B</span>
              <select
                className="sg-field__control"
                value={scanBId}
                onChange={(event) => setScanBId(event.target.value)}
              >
                <option value="" disabled>
                  Select scan
                </option>
                {scans.map((scan) => (
                  <option key={scan.id} value={String(scan.id)}>
                    #{scan.id} - task {scan.task} ({scan.findings_count} findings)
                  </option>
                ))}
              </select>
            </label>
            <button
              type="submit"
              className="sg-button sg-button--primary"
              disabled={!canCompare}
            >
              Compare
            </button>
          </form>
        </>
      )}

      <ConfirmModal
        open={pendingDelete !== null}
        title="Delete scan?"
        description={
          pendingDelete ? (
            <p>
              Scan #{pendingDelete.id} (task {pendingDelete.task}) will be
              hidden from this artifact. This is a soft-delete: the record
              stays in the database.
            </p>
          ) : null
        }
        confirmLabel="Delete"
        confirmTone="danger"
        isPending={deleteScan.isPending}
        errorMessage={deleteError}
        onConfirm={confirmDelete}
        onCancel={() => {
          if (!deleteScan.isPending) {
            setPendingDelete(null);
            deleteScan.reset();
          }
        }}
      />
    </section>
  );
}
