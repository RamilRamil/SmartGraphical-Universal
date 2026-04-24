import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { SgApiError } from "../api/client";
import { useGraph, useScan } from "../api/hooks";
import { FindingCard } from "../components/FindingCard";
import { GraphView } from "../components/GraphView";

const CONFIDENCE_FILTERS = ["any", "high", "medium", "low"] as const;
type ConfidenceFilter = (typeof CONFIDENCE_FILTERS)[number];

type ResultsTab = "findings" | "graph";

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const parsedScanId = scanId ? Number.parseInt(scanId, 10) : undefined;
  const scanQuery = useScan(
    Number.isFinite(parsedScanId) ? (parsedScanId as number) : undefined,
  );
  const [filter, setFilter] = useState<ConfidenceFilter>("any");
  const [tab, setTab] = useState<ResultsTab>("findings");
  const graphQuery = useGraph(
    Number.isFinite(parsedScanId) ? (parsedScanId as number) : undefined,
  );

  const filtered = useMemo(() => {
    const list = scanQuery.data?.findings ?? [];
    if (filter === "any") return list;
    return list.filter((finding) => finding.confidence === filter);
  }, [filter, scanQuery.data]);

  if (!parsedScanId || Number.isNaN(parsedScanId)) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Scan</h1>
        <p className="sg-banner sg-banner--error">Invalid scan id.</p>
      </section>
    );
  }

  if (scanQuery.isPending) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Scan #{parsedScanId}</h1>
        <p className="sg-page__hint">Loading...</p>
      </section>
    );
  }

  if (scanQuery.error) {
    const message =
      scanQuery.error instanceof SgApiError
        ? `${scanQuery.error.code}: ${scanQuery.error.message}`
        : (scanQuery.error as Error).message;
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Scan #{parsedScanId}</h1>
        <p className="sg-banner sg-banner--error">Failed to load scan: {message}</p>
      </section>
    );
  }

  const detail = scanQuery.data;
  if (!detail) {
    return (
      <section className="sg-page">
        <h1 className="sg-page__title">Scan #{parsedScanId}</h1>
        <p className="sg-banner sg-banner--error">Scan not found.</p>
      </section>
    );
  }

  const { scan, artifact, findings } = detail;
  const isError = scan.status === "error";
  const graphAvailable =
    !isError &&
    scan.task === "all" &&
    graphQuery.data !== undefined &&
    graphQuery.data.available === true;
  const graphData =
    graphAvailable && graphQuery.data && graphQuery.data.available
      ? graphQuery.data.graph.model_summary.graph
      : undefined;

  return (
    <section className="sg-page">
      <div className="sg-page__header">
        <h1 className="sg-page__title">Scan #{scan.id}</h1>
        <Link to="/history" className="sg-link">
          All scans
        </Link>
      </div>

      {isError && (
        <p className="sg-banner sg-banner--error">
          <strong>Analysis failed ({scan.error_code || "unknown"}):</strong>{" "}
          {scan.error_message || "no details provided"}
        </p>
      )}

      <div className="sg-meta">
        <div>
          <span className="sg-meta__label">Task</span>
          <span className="sg-meta__value">{scan.task}</span>
        </div>
        <div>
          <span className="sg-meta__label">Mode</span>
          <span className="sg-meta__value">{scan.mode}</span>
        </div>
        <div>
          <span className="sg-meta__label">Status</span>
          <span className={`sg-meta__value sg-status sg-status--${scan.status}`}>
            {scan.status}
          </span>
        </div>
        <div>
          <span className="sg-meta__label">Duration</span>
          <span className="sg-meta__value">{formatDuration(scan.duration_ms)}</span>
        </div>
        <div>
          <span className="sg-meta__label">Findings</span>
          <span className="sg-meta__value">{scan.findings_count}</span>
        </div>
        <div>
          <span className="sg-meta__label">Tool version</span>
          <span className="sg-meta__value sg-meta__value--mono">
            {scan.tool_version || "unknown"}
          </span>
        </div>
        <div>
          <span className="sg-meta__label">Rules catalog</span>
          <span className="sg-meta__value sg-meta__value--mono">
            {scan.rules_catalog_hash ? scan.rules_catalog_hash.slice(0, 12) : "-"}
          </span>
        </div>
        {artifact && (
          <div>
            <span className="sg-meta__label">Artifact</span>
            <Link
              to={`/artifacts/${artifact.id}`}
              className="sg-meta__value sg-link"
            >
              #{artifact.id} {artifact.filename}
            </Link>
          </div>
        )}
      </div>

      {!isError && (
        <>
          <div className="sg-tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={tab === "findings"}
              className={`sg-tabs__tab${tab === "findings" ? " sg-tabs__tab--active" : ""}`}
              onClick={() => setTab("findings")}
            >
              Findings ({findings.length})
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tab === "graph"}
              className={`sg-tabs__tab${tab === "graph" ? " sg-tabs__tab--active" : ""}`}
              onClick={() => setTab("graph")}
              disabled={!graphAvailable}
              title={
                graphAvailable
                  ? "Open graph view"
                  : scan.task === "all"
                    ? "Graph is being loaded or unavailable"
                    : "Graph is only available for scans run with task 'all'"
              }
            >
              Graph
            </button>
          </div>

          {tab === "findings" && (
            <>
              <div className="sg-filter">
                <label className="sg-field">
                  <span className="sg-field__label">Confidence</span>
                  <select
                    className="sg-field__control"
                    value={filter}
                    onChange={(event) =>
                      setFilter(event.target.value as ConfidenceFilter)
                    }
                  >
                    {CONFIDENCE_FILTERS.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                </label>
                <span className="sg-filter__count">
                  {filtered.length} / {findings.length} findings
                </span>
              </div>

              {filtered.length === 0 ? (
                <p className="sg-page__hint">
                  No findings match the current filter.
                </p>
              ) : (
                <div className="sg-findings">
                  {filtered.map((finding, index) => (
                    <FindingCard
                      key={`${finding.task_id}-${finding.rule_id}-${index}`}
                      finding={finding}
                    />
                  ))}
                </div>
              )}
            </>
          )}

          {tab === "graph" && (
            <>
              {graphQuery.isPending && (
                <p className="sg-page__hint">Loading graph...</p>
              )}
              {graphQuery.error && (
                <p className="sg-banner sg-banner--error">
                  Failed to load graph:{" "}
                  {graphQuery.error instanceof SgApiError
                    ? `${graphQuery.error.code}: ${graphQuery.error.message}`
                    : (graphQuery.error as Error).message}
                </p>
              )}
              {graphData ? (
                <GraphView graph={graphData} />
              ) : (
                !graphQuery.isPending && (
                  <p className="sg-page__hint">
                    Graph payload is not available for this scan. Re-run the
                    analysis with task &quot;all&quot; on a newer tool version.
                  </p>
                )
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}
