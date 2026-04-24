import { Link, useParams } from "react-router-dom";

import { SgApiError } from "../api/client";
import { useDiff } from "../api/hooks";
import { FindingCard } from "../components/FindingCard";
import type { Finding } from "../api/types";

function formatApiError(err: unknown): string {
  if (err instanceof SgApiError) return `${err.code}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

function parseScanId(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function FindingsSection({
  title,
  tone,
  findings,
  emptyMessage,
}: {
  title: string;
  tone: "added" | "removed";
  findings: Finding[];
  emptyMessage: string;
}) {
  return (
    <div className={`sg-diff__section sg-diff__section--${tone}`}>
      <h2 className="sg-section__title">
        {title}{" "}
        <span className="sg-diff__count">{findings.length}</span>
      </h2>
      {findings.length === 0 ? (
        <p className="sg-page__hint">{emptyMessage}</p>
      ) : (
        <div className="sg-findings">
          {findings.map((finding, index) => (
            <FindingCard
              key={`${tone}-${finding.task_id}-${finding.rule_id}-${index}`}
              finding={finding}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function DiffPage() {
  const { scanA, scanB } = useParams<{ scanA: string; scanB: string }>();
  const parsedA = parseScanId(scanA);
  const parsedB = parseScanId(scanB);
  const diffQuery = useDiff(parsedA, parsedB);

  if (parsedA === undefined || parsedB === undefined) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Diff</h1>
        <p className="sg-banner sg-banner--error">Invalid scan ids.</p>
      </section>
    );
  }

  if (parsedA === parsedB) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Diff</h1>
        <p className="sg-banner sg-banner--error">
          Cannot compare a scan against itself.
        </p>
      </section>
    );
  }

  if (diffQuery.isPending) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">
          Diff #{parsedA} vs #{parsedB}
        </h1>
        <p className="sg-page__hint">Loading...</p>
      </section>
    );
  }

  if (diffQuery.error) {
    const err = diffQuery.error;
    const code = err instanceof SgApiError ? err.code : null;
    const message = formatApiError(err);
    const humanReadable =
      code === "diff_artifact_mismatch"
        ? "These two scans belong to different artifacts and cannot be compared. Diff is only available within the same artifact."
        : code === "not_found"
          ? "One of the scans was not found (it may have been soft-deleted)."
          : message;
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">
          Diff #{parsedA} vs #{parsedB}
        </h1>
        <p className="sg-banner sg-banner--error">{humanReadable}</p>
        <p className="sg-page__hint">
          <Link className="sg-link" to={`/scans/${parsedA}`}>
            Open scan #{parsedA}
          </Link>{" "}
          ·{" "}
          <Link className="sg-link" to={`/scans/${parsedB}`}>
            Open scan #{parsedB}
          </Link>
        </p>
      </section>
    );
  }

  const diff = diffQuery.data;
  if (!diff) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Diff</h1>
        <p className="sg-banner sg-banner--error">No diff payload.</p>
      </section>
    );
  }

  return (
    <section className="sg-page">
      <div className="sg-page__header">
        <h1 className="sg-page__title">
          Diff #{diff.scan_a_id} vs #{diff.scan_b_id}
        </h1>
        <Link
          to={`/artifacts/${diff.artifact_id}`}
          className="sg-link"
        >
          Artifact #{diff.artifact_id}
        </Link>
      </div>

      <div className="sg-meta">
        <div>
          <span className="sg-meta__label">Added</span>
          <span className="sg-meta__value">{diff.added.length}</span>
        </div>
        <div>
          <span className="sg-meta__label">Removed</span>
          <span className="sg-meta__value">{diff.removed.length}</span>
        </div>
        <div>
          <span className="sg-meta__label">Unchanged</span>
          <span className="sg-meta__value">{diff.unchanged_count}</span>
        </div>
        <div>
          <span className="sg-meta__label">Scan A</span>
          <Link to={`/scans/${diff.scan_a_id}`} className="sg-meta__value sg-link">
            #{diff.scan_a_id}
          </Link>
        </div>
        <div>
          <span className="sg-meta__label">Scan B</span>
          <Link to={`/scans/${diff.scan_b_id}`} className="sg-meta__value sg-link">
            #{diff.scan_b_id}
          </Link>
        </div>
      </div>

      <FindingsSection
        title="Added in Scan B"
        tone="added"
        findings={diff.added}
        emptyMessage="Nothing new was detected."
      />
      <FindingsSection
        title="Removed from Scan A"
        tone="removed"
        findings={diff.removed}
        emptyMessage="No findings disappeared."
      />
    </section>
  );
}
