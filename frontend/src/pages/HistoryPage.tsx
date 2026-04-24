import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { SgApiError } from "../api/client";
import { useArtifacts, useDeleteScan, useScans } from "../api/hooks";
import { ConfirmModal } from "../components/ConfirmModal";
import type { ArtifactLookup } from "../components/ScansTable";
import { ScansTable } from "../components/ScansTable";
import type { Scan } from "../api/types";

function formatApiError(err: unknown): string {
  if (err instanceof SgApiError) return `${err.code}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

export function HistoryPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const artifactIdRaw = searchParams.get("artifact_id");
  const artifactFilter = artifactIdRaw ? Number.parseInt(artifactIdRaw, 10) : null;
  const artifactIdForQuery =
    artifactFilter !== null && Number.isFinite(artifactFilter)
      ? artifactFilter
      : null;

  const scansQuery = useScans(artifactIdForQuery);
  const artifactsQuery = useArtifacts();
  const deleteScan = useDeleteScan();

  const [pendingDelete, setPendingDelete] = useState<Scan | null>(null);

  const artifactLookup: ArtifactLookup = useMemo(() => {
    const items = artifactsQuery.data?.items ?? [];
    const map = new Map<number, { filename: string; language: string }>();
    for (const artifact of items) {
      map.set(artifact.id, {
        filename: artifact.filename,
        language: artifact.language,
      });
    }
    return (id: number) => map.get(id);
  }, [artifactsQuery.data]);

  const scans = (scansQuery.data?.items ?? []).filter(
    (scan) => !scan.deleted_at,
  );

  function clearFilter() {
    const next = new URLSearchParams(searchParams);
    next.delete("artifact_id");
    setSearchParams(next, { replace: true });
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
        <h1 className="sg-page__title">History</h1>
        {artifactIdForQuery !== null && (
          <button type="button" className="sg-button sg-button--ghost" onClick={clearFilter}>
            Clear artifact filter (#{artifactIdForQuery})
          </button>
        )}
      </div>

      <ScansTable
        scans={scans}
        isPending={scansQuery.isPending}
        errorMessage={
          scansQuery.error ? formatApiError(scansQuery.error) : null
        }
        emptyMessage={
          artifactIdForQuery !== null
            ? "No scans for this artifact yet."
            : "No scans yet. Upload a file to start."
        }
        showArtifactColumn={artifactIdForQuery === null}
        artifactLookup={artifactLookup}
        onDelete={(scan) => {
          deleteScan.reset();
          setPendingDelete(scan);
        }}
      />

      <ConfirmModal
        open={pendingDelete !== null}
        title="Delete scan?"
        description={
          pendingDelete ? (
            <p>
              Scan #{pendingDelete.id} (task {pendingDelete.task}, mode{" "}
              {pendingDelete.mode}) will be hidden from the history. This is a
              soft-delete: the record stays in the database.
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
