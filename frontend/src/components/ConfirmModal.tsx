import { useEffect, useRef } from "react";
import type { ReactNode } from "react";

type ConfirmModalProps = {
  open: boolean;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  confirmTone?: "danger" | "primary";
  isPending?: boolean;
  errorMessage?: string | null;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmModal({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  confirmTone = "primary",
  isPending = false,
  errorMessage,
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    cancelRef.current?.focus();
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !isPending) {
        onCancel();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onCancel, isPending]);

  if (!open) return null;

  const confirmClass =
    confirmTone === "danger"
      ? "sg-button sg-button--danger"
      : "sg-button sg-button--primary";

  return (
    <div
      className="sg-modal-backdrop"
      role="presentation"
      onClick={() => {
        if (!isPending) onCancel();
      }}
    >
      <div
        className="sg-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sg-modal-title"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 className="sg-modal__title" id="sg-modal-title">
          {title}
        </h2>
        {description && <div className="sg-modal__body">{description}</div>}
        {errorMessage && (
          <p className="sg-banner sg-banner--error">{errorMessage}</p>
        )}
        <div className="sg-modal__actions">
          <button
            ref={cancelRef}
            type="button"
            className="sg-button"
            onClick={onCancel}
            disabled={isPending}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            className={confirmClass}
            onClick={onConfirm}
            disabled={isPending}
          >
            {isPending ? "Working..." : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
