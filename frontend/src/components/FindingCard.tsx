import { useState } from "react";

import type { Finding } from "../api/types";

type FindingCardProps = {
  finding: Finding;
  defaultOpen?: boolean;
  /** When provided, renders a "Show on graph" action that focuses this finding's node. */
  onShowOnGraph?: () => void;
  /** Feature 013: set this finding's verdict. */
  onSetVerdict?: (status: "false_positive" | "accepted", note: string) => void;
  /** Feature 013: clear this finding's verdict. */
  onClearVerdict?: () => void;
};

export function FindingCard({
  finding,
  defaultOpen = false,
  onShowOnGraph,
  onSetVerdict,
  onClearVerdict,
}: FindingCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  const [note, setNote] = useState(finding.verdict?.note ?? "");
  const evidenceCount = finding.evidences?.length ?? 0;
  const verdictStatus = finding.verdict?.status ?? null;
  return (
    <article className="sg-finding">
      <header
        className="sg-finding__header"
        onClick={() => setOpen((value) => !value)}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            setOpen((value) => !value);
          }
        }}
      >
        <div className="sg-finding__titlerow">
          <span className="sg-finding__task">#{finding.task_id}</span>
          <span className="sg-finding__title">
            {finding.title || finding.rule_id}
          </span>
        </div>
        {finding.source_file?.trim() && (
          <div className="sg-form__hint" style={{ marginTop: "0.25rem" }}>
            file: {finding.source_file.trim()}
          </div>
        )}
        <div className="sg-finding__meta">
          <span className={`sg-badge sg-badge--${finding.confidence || "unknown"}`}>
            {finding.confidence || "unknown"}
          </span>
          <span className="sg-finding__category">{finding.category}</span>
          {verdictStatus && (
            <span className={`sg-badge sg-verdict--${verdictStatus}`}>
              {verdictStatus === "false_positive" ? "false positive" : verdictStatus}
            </span>
          )}
          {onShowOnGraph && (
            <button
              type="button"
              className="sg-button sg-button--ghost sg-finding__graph-btn"
              onClick={(event) => {
                event.stopPropagation();
                onShowOnGraph();
              }}
              title="Focus this finding's node on the graph"
            >
              Show on graph
            </button>
          )}
          <span className="sg-finding__toggle">{open ? "-" : "+"}</span>
        </div>
      </header>
      {open && (
        <div className="sg-finding__body">
          {onSetVerdict && (
            <div className="sg-finding__verdict">
              <span className="sg-finding__verdict-label">
                Verdict: {verdictStatus ?? "untriaged"}
              </span>
              <input
                type="text"
                className="sg-field__control sg-finding__verdict-note"
                placeholder="note (optional)"
                value={note}
                onChange={(event) => setNote(event.target.value)}
              />
              <button
                type="button"
                className="sg-button sg-button--ghost"
                onClick={() => onSetVerdict("false_positive", note)}
              >
                False positive
              </button>
              <button
                type="button"
                className="sg-button sg-button--ghost"
                onClick={() => onSetVerdict("accepted", note)}
              >
                Accepted
              </button>
              {verdictStatus && onClearVerdict && (
                <button
                  type="button"
                  className="sg-button sg-button--ghost"
                  onClick={() => onClearVerdict()}
                >
                  Clear
                </button>
              )}
            </div>
          )}
          {finding.message && (
            <p className="sg-finding__message">{finding.message}</p>
          )}
          {finding.remediation_hint && (
            <p className="sg-finding__hint">
              <strong>Hint:</strong> {finding.remediation_hint}
            </p>
          )}
          {evidenceCount > 0 && (
            <ul className="sg-evidence">
              {finding.evidences.map((evidence, index) => (
                <li key={index} className="sg-evidence__item">
                  <div className="sg-evidence__summary">{evidence.summary}</div>
                  {(evidence.type_name || evidence.function_name) && (
                    <div className="sg-evidence__location">
                      {evidence.type_name}
                      {evidence.function_name ? `.${evidence.function_name}` : ""}
                    </div>
                  )}
                  {(Array.isArray(evidence.line_numbers) && evidence.line_numbers.length > 0) ||
                  (typeof evidence.line_number === "number" && evidence.line_number > 0) ? (
                    <div className="sg-evidence__reason">
                      lines:{" "}
                      {Array.isArray(evidence.line_numbers) && evidence.line_numbers.length > 0
                        ? evidence.line_numbers.join(", ")
                        : String(evidence.line_number)}
                    </div>
                  ) : null}
                  {evidence.statement && (
                    <pre className="sg-evidence__statement">{evidence.statement}</pre>
                  )}
                  {evidence.confidence_reason && (
                    <div className="sg-evidence__reason">
                      reason: {evidence.confidence_reason}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </article>
  );
}
