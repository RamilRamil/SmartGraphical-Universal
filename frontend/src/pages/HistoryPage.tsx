import { useEffect, useMemo, useState } from "react";
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
  const showArtifactColumn = artifactIdForQuery === null;

  const scansQuery = useScans(artifactIdForQuery);
  const artifactsQuery = useArtifacts();
  const deleteScan = useDeleteScan();

  const [pendingDelete, setPendingDelete] = useState<Scan | null>(null);
  const [pendingBulkDelete, setPendingBulkDelete] = useState(false);
  const [selectedScanIds, setSelectedScanIds] = useState<number[]>([]);
  const [artifactSortDirection, setArtifactSortDirection] = useState<"none" | "asc" | "desc">("none");

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
  const visibleScans = useMemo(() => {
    if (!showArtifactColumn || artifactSortDirection === "none") {
      return scans;
    }
    return [...scans].sort((a, b) => {
      const aName = artifactLookup(a.artifact_id)?.filename ?? "";
      const bName = artifactLookup(b.artifact_id)?.filename ?? "";
      const byName = aName.localeCompare(bName, undefined, { sensitivity: "base" });
      if (byName !== 0) {
        return artifactSortDirection === "asc" ? byName : -byName;
      }
      return artifactSortDirection === "asc"
        ? a.artifact_id - b.artifact_id
        : b.artifact_id - a.artifact_id;
    });
  }, [artifactLookup, artifactSortDirection, scans, showArtifactColumn]);
  const selectedCount = selectedScanIds.length;

  useEffect(() => {
    const visibleScanIds = new Set(visibleScans.map((scan) => scan.id));
    setSelectedScanIds((prev) =>
      prev.filter((scanId) => visibleScanIds.has(scanId)),
    );
  }, [visibleScans]);

  function clearFilter() {
    const next = new URLSearchParams(searchParams);
    next.delete("artifact_id");
    setSearchParams(next, { replace: true });
  }

  async function confirmDelete() {
    if (!pendingDelete && !pendingBulkDelete) return;
    try {
      if (pendingDelete) {
        await deleteScan.mutateAsync(pendingDelete.id);
      } else {
        for (const scanId of selectedScanIds) {
          await deleteScan.mutateAsync(scanId);
        }
        setSelectedScanIds([]);
      }
      setPendingDelete(null);
      setPendingBulkDelete(false);
    } catch {
      // surfaced via deleteScan.error
    }
  }

  const deleteError = deleteScan.error ? formatApiError(deleteScan.error) : null;

  return (
    <section className="sg-page">
      <div className="sg-page__header">
        <h1 className="sg-page__title">History</h1>
        <div className="sg-history__actions">
          <button
            type="button"
            className="sg-button sg-button--danger"
            disabled={selectedCount === 0}
            onClick={() => {
              deleteScan.reset();
              setPendingDelete(null);
              setPendingBulkDelete(true);
            }}
          >
            Delete selected ({selectedCount})
          </button>
        </div>
        {artifactIdForQuery !== null && (
          <button type="button" className="sg-button sg-button--ghost" onClick={clearFilter}>
            Clear artifact filter (#{artifactIdForQuery})
          </button>
        )}
      </div>

      <ScansTable
        scans={visibleScans}
        isPending={scansQuery.isPending}
        errorMessage={
          scansQuery.error ? formatApiError(scansQuery.error) : null
        }
        emptyMessage={
          artifactIdForQuery !== null
            ? "No scans for this artifact yet."
            : "No scans yet. Upload a file to start."
        }
        showArtifactColumn={showArtifactColumn}
        artifactLookup={artifactLookup}
        artifactSortDirection={artifactSortDirection}
        onArtifactSortToggle={() => {
          setArtifactSortDirection((prev) => {
            if (prev === "none") return "asc";
            if (prev === "asc") return "desc";
            return "none";
          });
        }}
        selectedScanIds={selectedScanIds}
        onToggleSelect={(scanId, isSelected) => {
          setSelectedScanIds((prev) => {
            if (isSelected) {
              if (prev.includes(scanId)) return prev;
              return [...prev, scanId];
            }
            return prev.filter((id) => id !== scanId);
          });
        }}
        onToggleSelectAll={(isSelected) => {
          if (!isSelected) {
            setSelectedScanIds([]);
            return;
          }
          setSelectedScanIds(visibleScans.map((scan) => scan.id));
        }}
        onDelete={(scan) => {
          deleteScan.reset();
          setPendingBulkDelete(false);
          setPendingDelete(scan);
        }}
      />

      <ConfirmModal
        open={pendingDelete !== null || pendingBulkDelete}
        title={pendingDelete ? "Delete scan?" : "Delete selected scans?"}
        description={
          pendingDelete ? (
            <p>
              Scan #{pendingDelete.id} (task {pendingDelete.task}, mode{" "}
              {pendingDelete.mode}) will be hidden from the history. This is a
              soft-delete: the record stays in the database.
            </p>
          ) : (
            <p>
              {selectedCount} scan(s) will be hidden from the history. This is a
              soft-delete: records stay in the database.
            </p>
          )
        }
        confirmLabel={pendingDelete ? "Delete" : `Delete ${selectedCount} scan(s)`}
        confirmTone="danger"
        isPending={deleteScan.isPending}
        errorMessage={deleteError}
        onConfirm={confirmDelete}
        onCancel={() => {
          if (!deleteScan.isPending) {
            setPendingDelete(null);
            setPendingBulkDelete(false);
            deleteScan.reset();
          }
        }}
      />
    </section>
  );
}
