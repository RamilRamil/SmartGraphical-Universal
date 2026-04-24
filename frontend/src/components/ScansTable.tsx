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
}: ScansTableProps) {
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
            <th>Scan</th>
            {showArtifactColumn && <th>Artifact</th>}
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
