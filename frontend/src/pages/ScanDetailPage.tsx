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

function normalizeContractName(filename: string | undefined, scanId: number): string {
  if (!filename) return `scan-${scanId}`;
  const noExtension = filename.replace(/\.[^.]+$/, "");
  const normalized = noExtension
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return normalized || `scan-${scanId}`;
}

function buildLocation(finding: {
  evidences?: Array<{
    type_name?: string;
    function_name?: string;
    line_numbers?: number[];
    line_number?: number;
  }>;
}): string {
  const evidence = finding.evidences?.[0];
  if (!evidence) return "unknown";
  const scope = [evidence.type_name, evidence.function_name].filter(Boolean).join(".");
  const lines =
    Array.isArray(evidence.line_numbers) && evidence.line_numbers.length > 0
      ? evidence.line_numbers.join(", ")
      : typeof evidence.line_number === "number"
        ? `${evidence.line_number}`
        : "";
  if (scope && lines) return `${scope} (lines: ${lines})`;
  if (scope) return scope;
  if (lines) return `lines: ${lines}`;
  return "unknown";
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
  const hasFindings = findings.length > 0;

  const handleDownloadFindingsMd = () => {
    if (!hasFindings) return;
    const contractName = normalizeContractName(artifact?.filename, scan.id);
    const reportLines: string[] = [
      `# Findings Report: ${contractName}`,
      "",
      `- scan_id: ${scan.id}`,
      `- artifact: ${artifact?.filename || "unknown"}`,
      `- findings_count: ${findings.length}`,
      "",
      "## Findings",
      "",
    ];

    findings.forEach((finding, index) => {
      const location = buildLocation(finding);
      reportLines.push(`### ${index + 1}. ${finding.title || finding.rule_id}`);
      reportLines.push("");
      reportLines.push(`- severity: ${finding.confidence || "unknown"}`);
      reportLines.push(`- location: ${location}`);
      reportLines.push(`- description: ${finding.message || "n/a"}`);
      reportLines.push(`- recommendation: ${finding.remediation_hint || "n/a"}`);
      reportLines.push("");
    });

    const markdown = reportLines.join("\n");
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `findings-${contractName}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

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
                <button
                  type="button"
                  className="sg-button sg-button--ghost"
                  onClick={handleDownloadFindingsMd}
                  disabled={!hasFindings}
                >
                  Export MD
                </button>
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
