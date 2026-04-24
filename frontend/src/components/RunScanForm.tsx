import { useState } from "react";
import type { FormEvent } from "react";

import { SgApiError } from "../api/client";
import { useCreateScan, useTasks } from "../api/hooks";
import type { Scan } from "../api/types";

const ALLOWED_MODES = ["auditor", "legacy", "explore"] as const;
type Mode = (typeof ALLOWED_MODES)[number];

type RunScanFormProps = {
  artifactId: number;
  language: string;
  onSuccess: (scan: Scan) => void;
  submitLabel?: string;
  defaultMode?: Mode;
};

function formatApiError(err: unknown): string {
  if (err instanceof SgApiError) return `${err.code}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

export function RunScanForm({
  artifactId,
  language,
  onSuccess,
  submitLabel = "Run analysis",
  defaultMode = "auditor",
}: RunScanFormProps) {
  const [mode, setMode] = useState<Mode>(defaultMode);
  const [task, setTask] = useState<string>("");

  const tasksQuery = useTasks(language);
  const createScanMutation = useCreateScan(artifactId);

  const tasks = tasksQuery.data?.tasks ?? [];
  const tasksError = tasksQuery.error ? formatApiError(tasksQuery.error) : null;
  const runError = createScanMutation.error
    ? formatApiError(createScanMutation.error)
    : null;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!task) return;
    try {
      const scan = await createScanMutation.mutateAsync({ task, mode });
      onSuccess(scan);
    } catch {
      // surfaced via runError
    }
  }

  return (
    <form className="sg-form" onSubmit={handleSubmit}>
      {tasksError && (
        <p className="sg-banner sg-banner--error">
          Failed to load tasks: {tasksError}
        </p>
      )}
      <label className="sg-field">
        <span className="sg-field__label">Mode</span>
        <select
          className="sg-field__control"
          value={mode}
          onChange={(event) => setMode(event.target.value as Mode)}
        >
          {ALLOWED_MODES.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
      <label className="sg-field">
        <span className="sg-field__label">Task</span>
        <select
          className="sg-field__control"
          value={task}
          onChange={(event) => setTask(event.target.value)}
          disabled={tasksQuery.isPending || tasks.length === 0}
        >
          <option value="" disabled>
            {tasksQuery.isPending ? "Loading..." : "Select task"}
          </option>
          {tasks.map((descriptor) => (
            <option key={descriptor.id} value={descriptor.id}>
              {descriptor.id === "all"
                ? descriptor.title
                : `${descriptor.id} - ${descriptor.title || descriptor.id}`}
            </option>
          ))}
        </select>
      </label>
      {runError && (
        <p className="sg-banner sg-banner--error">Run failed: {runError}</p>
      )}
      <div className="sg-form__actions">
        <button
          type="submit"
          className="sg-button sg-button--primary"
          disabled={!task || createScanMutation.isPending}
        >
          {createScanMutation.isPending ? "Running..." : submitLabel}
        </button>
      </div>
    </form>
  );
}
