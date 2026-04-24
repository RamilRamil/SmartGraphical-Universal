import { useState } from "react";

import type { Finding } from "../api/types";

type FindingCardProps = {
  finding: Finding;
  defaultOpen?: boolean;
};

export function FindingCard({ finding, defaultOpen = false }: FindingCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  const evidenceCount = finding.evidences?.length ?? 0;
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
        <div className="sg-finding__meta">
          <span className={`sg-badge sg-badge--${finding.confidence || "unknown"}`}>
            {finding.confidence || "unknown"}
          </span>
          <span className="sg-finding__category">{finding.category}</span>
          <span className="sg-finding__toggle">{open ? "-" : "+"}</span>
        </div>
      </header>
      {open && (
        <div className="sg-finding__body">
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
