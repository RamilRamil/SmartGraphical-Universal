import { Link } from "react-router-dom";

import type { Scan } from "../api/types";

export type ArtifactLookup = (
  artifactId: number,
) => { filename: string; language: string } | undefined;

type ScansTableProps = {
  scans: Scan[];
  isPending?: boolean;
  errorMessage?: string | null;
  emptyMessage?: string;
  showArtifactColumn?: boolean;
  artifactLookup?: ArtifactLookup;
  onDelete?: (scan: Scan) => void;
  selectedScanIds?: readonly number[];
  onToggleSelect?: (scanId: number, selected: boolean) => void;
  onToggleSelectAll?: (selected: boolean) => void;
  artifactSortDirection?: "none" | "asc" | "desc";
  onArtifactSortToggle?: () => void;
};

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function formatTimestamp(iso: string): string {
  if (!iso) return "-";
  const trimmed = iso.includes("T") ? iso.replace("T", " ").slice(0, 19) : iso;
  return trimmed;
}

export function ScansTable({
  scans,
  isPending = false,
  errorMessage,
  emptyMessage = "No scans yet.",
  showArtifactColumn = false,
  artifactLookup,
  onDelete,
  selectedScanIds = [],
  onToggleSelect,
  onToggleSelectAll,
  artifactSortDirection = "none",
  onArtifactSortToggle,
}: ScansTableProps) {
  const selectedSet = new Set(selectedScanIds);
  const hasSelection = Boolean(onToggleSelect);
  const allSelected = scans.length > 0 && scans.every((scan) => selectedSet.has(scan.id));

  if (isPending) {
    return <p className="sg-page__hint">Loading scans...</p>;
  }
  if (errorMessage) {
    return <p className="sg-banner sg-banner--error">{errorMessage}</p>;
  }
  if (scans.length === 0) {
    return <p className="sg-page__hint">{emptyMessage}</p>;
  }
  return (
    <div className="sg-table-wrap">
      <table className="sg-table">
        <thead>
          <tr>
            {hasSelection && (
              <th className="sg-table__select">
                <input
                  type="checkbox"
                  aria-label="Select all scans"
                  checked={allSelected}
                  onChange={(event) => {
                    onToggleSelectAll?.(event.target.checked);
                  }}
                />
              </th>
            )}
            <th>Scan</th>
            {showArtifactColumn && (
              <th>
                {onArtifactSortToggle ? (
                  <button
                    type="button"
                    className="sg-table__sort-button"
                    onClick={onArtifactSortToggle}
                  >
                    Artifact
                    <span className="sg-table__sort-indicator">
                      {artifactSortDirection === "asc"
                        ? "ASC"
                        : artifactSortDirection === "desc"
                          ? "DESC"
                          : "-"}
                    </span>
                  </button>
                ) : (
                  "Artifact"
                )}
              </th>
            )}
            <th>Task</th>
            <th>Mode</th>
            <th>Status</th>
            <th className="sg-table__num">Findings</th>
            <th className="sg-table__num">Duration</th>
            <th>Created</th>
            {onDelete && <th />}
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => {
            const artifact = artifactLookup?.(scan.artifact_id);
            return (
              <tr key={scan.id}>
                {hasSelection && (
                  <td className="sg-table__select">
                    <input
                      type="checkbox"
                      aria-label={`Select scan #${scan.id}`}
                      checked={selectedSet.has(scan.id)}
                      onChange={(event) => {
                        onToggleSelect?.(scan.id, event.target.checked);
                      }}
                    />
                  </td>
                )}
                <td>
                  <Link className="sg-link" to={`/scans/${scan.id}`}>
                    #{scan.id}
                  </Link>
                </td>
                {showArtifactColumn && (
                  <td>
                    <Link
                      className="sg-link"
                      to={`/artifacts/${scan.artifact_id}`}
                    >
                      {artifact
                        ? `#${scan.artifact_id} ${artifact.filename}`
                        : `#${scan.artifact_id}`}
                    </Link>
                  </td>
                )}
                <td>{scan.task}</td>
                <td>{scan.mode}</td>
                <td>
                  <span className={`sg-status sg-status--${scan.status}`}>
                    {scan.status}
                  </span>
                </td>
                <td className="sg-table__num">{scan.findings_count}</td>
                <td className="sg-table__num">
                  {formatDuration(scan.duration_ms)}
                </td>
                <td>{formatTimestamp(scan.created_at)}</td>
                {onDelete && (
                  <td>
                    <button
                      type="button"
                      className="sg-button sg-button--ghost"
                      onClick={() => onDelete(scan)}
                    >
                      Delete
                    </button>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
