import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { SgApiError } from "../api/client";
import {
  useArtifact,
  useDeleteScan,
  useGraph,
  useScan,
  useScans,
} from "../api/hooks";
import { ConfirmModal } from "../components/ConfirmModal";
import { FindingCard } from "../components/FindingCard";
import { GraphView } from "../components/GraphView";
import { RunScanForm } from "../components/RunScanForm";
import { ScansTable } from "../components/ScansTable";
import type { Scan } from "../api/types";

const CONFIDENCE_FILTERS = ["any", "high", "medium", "low"] as const;
type ConfidenceFilter = (typeof CONFIDENCE_FILTERS)[number];
type ResultsTab = "findings" | "graph";

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

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
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
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [filter, setFilter] = useState<ConfidenceFilter>("any");
  const [tab, setTab] = useState<ResultsTab>("findings");

  const scans = useMemo(
    () =>
      (scansQuery.data?.items ?? []).filter((scan) => !scan.deleted_at),
    [scansQuery.data],
  );
  const selectedScanIdNumber =
    selectedScanId !== "" ? Number.parseInt(selectedScanId, 10) : undefined;
  const selectedScanIsValid = Number.isFinite(selectedScanIdNumber);
  const selectedScanQuery = useScan(
    selectedScanIsValid ? (selectedScanIdNumber as number) : undefined,
  );
  const selectedGraphQuery = useGraph(
    selectedScanIsValid ? (selectedScanIdNumber as number) : undefined,
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
  const selectedDetail = selectedScanQuery.data;
  const selectedScan = selectedDetail?.scan;
  const selectedFindings = selectedDetail?.findings ?? [];
  const selectedScanError = selectedScan?.status === "error";
  const selectedGraphAvailable =
    !selectedScanError &&
    selectedScan?.task === "all" &&
    selectedGraphQuery.data !== undefined &&
    selectedGraphQuery.data.available === true;
  const selectedGraphData =
    selectedGraphAvailable &&
    selectedGraphQuery.data &&
    selectedGraphQuery.data.available
      ? selectedGraphQuery.data.graph.model_summary.graph
      : undefined;
  const filteredSelectedFindings = useMemo(() => {
    if (filter === "any") return selectedFindings;
    return selectedFindings.filter((finding) => finding.confidence === filter);
  }, [filter, selectedFindings]);

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

      <h2 className="sg-section__title">Report and graph by scan</h2>
      {scans.length === 0 ? (
        <p className="sg-page__hint">No scans available for report view yet.</p>
      ) : (
        <>
          <form className="sg-form sg-form--row" onSubmit={(event) => event.preventDefault()}>
            <label className="sg-field">
              <span className="sg-field__label">Select scan</span>
              <select
                className="sg-field__control"
                value={selectedScanId}
                onChange={(event) => {
                  setSelectedScanId(event.target.value);
                  setFilter("any");
                  setTab("findings");
                }}
              >
                <option value="" disabled>
                  Select scan
                </option>
                {scans.map((scan) => (
                  <option key={scan.id} value={String(scan.id)}>
                    #{scan.id} - {scan.task} ({scan.findings_count} findings)
                  </option>
                ))}
              </select>
            </label>
          </form>

          {selectedScanId === "" && (
            <p className="sg-page__hint">
              Select a scan to open its report and graph without re-running analysis.
            </p>
          )}

          {selectedScanId !== "" && selectedScanQuery.isPending && (
            <p className="sg-page__hint">Loading selected scan report...</p>
          )}

          {selectedScanId !== "" && selectedScanQuery.error && (
            <p className="sg-banner sg-banner--error">
              Failed to load selected scan: {formatApiError(selectedScanQuery.error)}
            </p>
          )}

          {selectedScanId !== "" && selectedDetail && selectedScan && (
            <>
              <div className="sg-meta">
                <div>
                  <span className="sg-meta__label">Selected scan</span>
                  <Link to={`/scans/${selectedScan.id}`} className="sg-meta__value sg-link">
                    #{selectedScan.id}
                  </Link>
                </div>
                <div>
                  <span className="sg-meta__label">Task</span>
                  <span className="sg-meta__value">{selectedScan.task}</span>
                </div>
                <div>
                  <span className="sg-meta__label">Mode</span>
                  <span className="sg-meta__value">{selectedScan.mode}</span>
                </div>
                <div>
                  <span className="sg-meta__label">Status</span>
                  <span className={`sg-meta__value sg-status sg-status--${selectedScan.status}`}>
                    {selectedScan.status}
                  </span>
                </div>
                <div>
                  <span className="sg-meta__label">Duration</span>
                  <span className="sg-meta__value">{formatDuration(selectedScan.duration_ms)}</span>
                </div>
                <div>
                  <span className="sg-meta__label">Findings</span>
                  <span className="sg-meta__value">{selectedFindings.length}</span>
                </div>
              </div>

              {selectedScanError && (
                <p className="sg-banner sg-banner--error">
                  Analysis failed ({selectedScan.error_code || "unknown"}):{" "}
                  {selectedScan.error_message || "no details provided"}
                </p>
              )}

              {!selectedScanError && (
                <>
                  <div className="sg-tabs" role="tablist">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={tab === "findings"}
                      className={`sg-tabs__tab${tab === "findings" ? " sg-tabs__tab--active" : ""}`}
                      onClick={() => setTab("findings")}
                    >
                      Findings ({selectedFindings.length})
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={tab === "graph"}
                      className={`sg-tabs__tab${tab === "graph" ? " sg-tabs__tab--active" : ""}`}
                      onClick={() => setTab("graph")}
                      disabled={!selectedGraphAvailable}
                      title={
                        selectedGraphAvailable
                          ? "Open graph view"
                          : selectedScan.task === "all"
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
                          {filteredSelectedFindings.length} / {selectedFindings.length} findings
                        </span>
                      </div>

                      {filteredSelectedFindings.length === 0 ? (
                        <p className="sg-page__hint">
                          No findings match the current filter.
                        </p>
                      ) : (
                        <div className="sg-findings">
                          {filteredSelectedFindings.map((finding, index) => (
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
                      {selectedGraphQuery.isPending && (
                        <p className="sg-page__hint">Loading graph...</p>
                      )}
                      {selectedGraphQuery.error && (
                        <p className="sg-banner sg-banner--error">
                          Failed to load graph: {formatApiError(selectedGraphQuery.error)}
                        </p>
                      )}
                      {selectedGraphData ? (
                        <GraphView graph={selectedGraphData} />
                      ) : (
                        !selectedGraphQuery.isPending && (
                          <p className="sg-page__hint">
                            Graph payload is not available for this scan. Run task
                            &quot;all&quot; to make graph available.
                          </p>
                        )
                      )}
                    </>
                  )}
                </>
              )}
            </>
          )}
        </>
      )}

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
