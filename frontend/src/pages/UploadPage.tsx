import { useMemo, useState, useEffect } from "react";
import type { ChangeEvent, DragEvent, FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { parseAnalysisMode, RunScanForm } from "../components/RunScanForm";
import { SgApiError } from "../api/client";
import { useUploadArtifactBundle, useUploadArtifactsBatch } from "../api/hooks";
import type { Artifact, BatchUploadResponse } from "../api/types";
import {
  defaultSelectedSubfolders,
  filterEntriesBySubfolders,
  inferBundleSubfolderSelection,
  type BundleSubfolderSelection,
} from "../lib/bundleFolderFilter";
import {
  ALLOWED_EXTENSIONS,
  coalesceFolderRelativePath,
  entryLeafFileName,
  isAllowedFileName,
  normalizeClientTreePath,
  readWebkitRelativePath,
} from "../lib/bundleUploadPaths";
import {
  parseUploadLayoutParam,
  saveUploadContextForScan,
  type UploadLayoutMode,
} from "../lib/uploadNavigationContext";

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
const MAX_BUNDLE_BYTES_TOTAL = 64 * 1024 * 1024;
/** Must match backend `smartgraphical/upload_limits.MAX_MULTIPART_SOURCE_FILES`. */
const MAX_BATCH_FILES = 1024;

type PendingEntry = {
  file: File;
  /** Raw relative path from folder picker or directory drop; null = flat / basename-only bundle */
  treePath: string | null;
};

function detectLanguage(fileName: string): string | null {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".sol")) return "solidity";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".c") || lower.endsWith(".h")) return "c";
  return null;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatApiError(err: unknown): string {
  if (err instanceof SgApiError) return `${err.code}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

function displayPathForEntry(entry: PendingEntry): string {
  if (entry.treePath) return entry.treePath.replace(/\\/g, "/");
  return entry.file.name;
}

function normalizeTreePath(entry: PendingEntry): string {
  return (entry.treePath ?? "").replace(/\\/g, "/");
}

function filterPendingBySubfolders(
  source: PendingEntry[],
  root: string,
  selected: ReadonlySet<string>,
): PendingEntry[] {
  return filterEntriesBySubfolders(
    source
      .filter((e): e is PendingEntry & { treePath: string } => e.treePath !== null)
      .map((e) => ({ ...e, treePath: normalizeTreePath(e) })),
    root,
    selected,
  );
}

/** Drop files whose extension is not in ALLOWED_EXTENSIONS (no error for whole batch). */
function filterEntriesByAllowedExtensions(entries: PendingEntry[]): PendingEntry[] {
  return entries.filter((e) => isAllowedFileName(entryLeafFileName(e)));
}

function validatePendingEntries(
  entries: PendingEntry[],
  layout: "separate" | "combined",
):
  | { ok: true; entries: PendingEntry[]; pathsForUpload?: string[] }
  | { ok: false; error: string } {
  if (entries.length === 0) {
    return { ok: false, error: "No files selected." };
  }
  if (entries.length > MAX_BATCH_FILES) {
    return { ok: false, error: `At most ${MAX_BATCH_FILES} files per batch.` };
  }

  let pathsForUpload: string[] | undefined;

  if (layout === "combined") {
    const rawPaths = entries.map((e) => e.treePath);
    const allNull = rawPaths.every((p) => p === null);
    const allSet = rawPaths.every((p) => p !== null);
    if (!allNull && !allSet) {
      return {
        ok: false,
        error:
          "Combined upload: use either a folder selection (paths for all files) or plain files (no mixed folder + loose files).",
      };
    }
    if (!allNull) {
      const normalized: string[] = [];
      for (const e of entries) {
        const n = normalizeClientTreePath(e.treePath!);
        if (!n.ok) return { ok: false, error: `${displayPathForEntry(e)}: ${n.error}` };
        normalized.push(n.path);
      }
      if (new Set(normalized).size !== normalized.length) {
        return { ok: false, error: "Duplicate paths after normalization." };
      }
      pathsForUpload = normalized;
    }

    let total = 0;
    for (const e of entries) {
      total += e.file.size;
    }
    if (total > MAX_BUNDLE_BYTES_TOTAL) {
      return {
        ok: false,
        error: `Bundle total size exceeds ${formatSize(MAX_BUNDLE_BYTES_TOTAL)}.`,
      };
    }
  }

  for (const e of entries) {
    if (e.file.size === 0) {
      return { ok: false, error: `${displayPathForEntry(e)} is empty.` };
    }
    if (e.file.size > MAX_UPLOAD_BYTES) {
      return { ok: false, error: `${displayPathForEntry(e)} exceeds ${formatSize(MAX_UPLOAD_BYTES)}.` };
    }
  }

  if (layout === "combined") {
    const langs = new Set<string>();
    for (const e of entries) {
      const d = detectLanguage(entryLeafFileName(e));
      if (d) langs.add(d);
    }
    if (langs.size > 1) {
      return {
        ok: false,
        error: "Combined upload requires files in a single language.",
      };
    }
  }

  return { ok: true, entries, pathsForUpload };
}

function getFileFromEntry(fileEntry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => {
    fileEntry.file(resolve, reject);
  });
}

async function readAllDirectoryEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  const chunks: FileSystemEntry[] = [];
  for (;;) {
    const batch = await new Promise<FileSystemEntry[]>((res, rej) => {
      reader.readEntries(res, rej);
    });
    if (batch.length === 0) break;
    chunks.push(...batch);
  }
  return chunks;
}

async function walkDirectoryEntry(dir: FileSystemDirectoryEntry, prefix: string): Promise<PendingEntry[]> {
  const out: PendingEntry[] = [];
  const reader = dir.createReader();
  const entries = await readAllDirectoryEntries(reader);
  for (const ent of entries) {
    if (ent.isFile) {
      const fe = ent as FileSystemFileEntry;
      const rel = prefix ? `${prefix}/${fe.name}` : fe.name;
      const file = await getFileFromEntry(fe);
      const treePath = coalesceFolderRelativePath(file, rel) ?? rel;
      const pend: PendingEntry = { file, treePath };
      if (!isAllowedFileName(entryLeafFileName(pend))) continue;
      out.push(pend);
    } else if (ent.isDirectory) {
      const de = ent as FileSystemDirectoryEntry;
      const nextPrefix = prefix ? `${prefix}/${de.name}` : de.name;
      out.push(...(await walkDirectoryEntry(de, nextPrefix)));
    }
  }
  return out;
}

export function UploadPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const defaultRunMode = parseAnalysisMode(searchParams.get("mode"));

  const [uploadLayout, setUploadLayout] = useState<UploadLayoutMode>(
    () => parseUploadLayoutParam(searchParams.get("layout")) ?? "separate",
  );

  useEffect(() => {
    const fromUrl = parseUploadLayoutParam(searchParams.get("layout"));
    if (fromUrl) setUploadLayout(fromUrl);
  }, [searchParams]);
  const [pendingEntries, setPendingEntries] = useState<PendingEntry[]>([]);
  const [stagedEntries, setStagedEntries] = useState<PendingEntry[]>([]);
  const [subfolderSelection, setSubfolderSelection] = useState<BundleSubfolderSelection | null>(
    null,
  );
  const [selectedSubfolders, setSelectedSubfolders] = useState<Set<string>>(() => new Set());
  const [clientError, setClientError] = useState<string | null>(null);
  const [extensionSkipNotice, setExtensionSkipNotice] = useState<string | null>(null);
  const [batchResult, setBatchResult] = useState<BatchUploadResponse | null>(null);
  const [bundleArtifact, setBundleArtifact] = useState<Artifact | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const batchMutation = useUploadArtifactsBatch();
  const bundleMutation = useUploadArtifactBundle();

  const previewLanguages = useMemo(() => {
    const langs = new Set<string>();
    for (const e of pendingEntries) {
      const d = detectLanguage(entryLeafFileName(e));
      if (d) langs.add(d);
    }
    return Array.from(langs).sort().join(", ") || "unknown";
  }, [pendingEntries]);

  const combinedUsesTreePaths = useMemo(() => {
    if (pendingEntries.length === 0) return false;
    return pendingEntries.every((e) => e.treePath !== null);
  }, [pendingEntries]);

  function commitFilteredEntries(
    source: PendingEntry[],
    meta: BundleSubfolderSelection | null,
    selected: ReadonlySet<string>,
    skippedExtensions: number,
  ) {
    let working = source;
    if (meta) {
      if (selected.size === 0) {
        setClientError("Select at least one subfolder to include in the bundle.");
        setPendingEntries([]);
        return;
      }
      working = filterPendingBySubfolders(source, meta.root, selected);
      if (working.length === 0) {
        setClientError("No supported source files in the selected subfolders.");
        setPendingEntries([]);
        return;
      }
    }
    const result = validatePendingEntries(working, uploadLayout);
    if (!result.ok) {
      setClientError(result.error);
      setPendingEntries([]);
      return;
    }
    setPendingEntries(result.entries);
    if (skippedExtensions > 0) {
      setExtensionSkipNotice(
        `Skipped ${skippedExtensions} file(s): extension not among ${ALLOWED_EXTENSIONS.join(", ")}.`,
      );
    }
  }

  function applyPendingEntries(entries: PendingEntry[]) {
    setClientError(null);
    setExtensionSkipNotice(null);
    setBatchResult(null);
    setBundleArtifact(null);
    const allowedEntries = filterEntriesByAllowedExtensions(entries);
    const skippedExtensions = entries.length - allowedEntries.length;
    if (allowedEntries.length === 0) {
      setPendingEntries([]);
      setStagedEntries([]);
      setSubfolderSelection(null);
      setSelectedSubfolders(new Set());
      if (entries.length === 0) {
        setClientError("No files selected.");
      } else {
        setClientError(
          `No supported source files (${ALLOWED_EXTENSIONS.join(", ")}). Skipped ${skippedExtensions} other file(s).`,
        );
      }
      return;
    }

    const allTreePaths =
      uploadLayout === "combined" &&
      allowedEntries.length > 0 &&
      allowedEntries.every((e) => e.treePath !== null);
    let meta: BundleSubfolderSelection | null = null;
    let selected = new Set<string>();

    if (allTreePaths) {
      const paths = allowedEntries.map((e) => normalizeTreePath(e));
      meta = inferBundleSubfolderSelection(paths);
      if (meta) {
        setStagedEntries(allowedEntries);
        setSubfolderSelection(meta);
        selected = defaultSelectedSubfolders(meta.subfolders);
        setSelectedSubfolders(selected);
      } else {
        setStagedEntries([]);
        setSubfolderSelection(null);
        setSelectedSubfolders(new Set());
      }
    } else {
      setStagedEntries([]);
      setSubfolderSelection(null);
      setSelectedSubfolders(new Set());
    }

    commitFilteredEntries(allowedEntries, meta, selected, skippedExtensions);
  }

  function handleSubfolderToggle(folderName: string, checked: boolean) {
    if (!subfolderSelection) return;
    const next = new Set(selectedSubfolders);
    if (checked) {
      next.add(folderName);
    } else {
      next.delete(folderName);
    }
    setSelectedSubfolders(next);
    commitFilteredEntries(stagedEntries, subfolderSelection, next, 0);
  }

  function handleSubfolderSelectAll() {
    if (!subfolderSelection) return;
    const next = defaultSelectedSubfolders(subfolderSelection.subfolders);
    setSelectedSubfolders(next);
    commitFilteredEntries(stagedEntries, subfolderSelection, next, 0);
  }

  function handleLayoutChange(next: "separate" | "combined") {
    setUploadLayout(next);
    setClientError(null);
    setExtensionSkipNotice(null);
    setBatchResult(null);
    setBundleArtifact(null);
    batchMutation.reset();
    bundleMutation.reset();
    if (pendingEntries.length === 0 && stagedEntries.length === 0) return;
    const source = stagedEntries.length > 0 ? stagedEntries : pendingEntries;
    applyPendingEntries(source);
  }

  function handleFlatFileInput(event: ChangeEvent<HTMLInputElement>) {
    const list = event.target.files;
    if (!list || list.length === 0) return;
    const entries: PendingEntry[] = Array.from(list).map((f) => ({
      file: f,
      treePath: coalesceFolderRelativePath(f, readWebkitRelativePath(f)),
    }));
    applyPendingEntries(entries);
    event.target.value = "";
  }

  function handleFolderFileInput(event: ChangeEvent<HTMLInputElement>) {
    const list = event.target.files;
    if (!list || list.length === 0) return;
    const entries: PendingEntry[] = Array.from(list).map((f) => ({
      file: f,
      treePath: coalesceFolderRelativePath(f, readWebkitRelativePath(f) ?? f.name),
    }));
    applyPendingEntries(entries);
    event.target.value = "";
  }

  async function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragOver(false);
    setClientError(null);
    setExtensionSkipNotice(null);
    setBatchResult(null);
    setBundleArtifact(null);

    if (uploadLayout === "combined") {
      const items = [...event.dataTransfer.items];
      const first = items[0];
      if (items.length === 1 && first && typeof first.webkitGetAsEntry === "function") {
        const entry = first.webkitGetAsEntry();
        if (entry?.isDirectory) {
          try {
            const walked = await walkDirectoryEntry(entry as FileSystemDirectoryEntry, "");
            applyPendingEntries(walked);
          } catch {
            setClientError("Could not read dropped folder.");
            setPendingEntries([]);
          }
          return;
        }
      }
    }

    const files = Array.from(event.dataTransfer.files);
    const entries: PendingEntry[] = files.map((f) => ({
      file: f,
      treePath: coalesceFolderRelativePath(f, readWebkitRelativePath(f)),
    }));
    applyPendingEntries(entries);
  }

  function handleDragOver(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragOver(true);
  }

  function handleDragLeave(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragOver(false);
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pendingEntries.length === 0) {
      if (subfolderSelection && selectedSubfolders.size === 0) {
        setClientError("Select at least one subfolder to include in the bundle.");
      }
      return;
    }
    const v = validatePendingEntries(pendingEntries, uploadLayout);
    if (!v.ok) {
      setClientError(v.error);
      return;
    }
    try {
      if (uploadLayout === "combined") {
        const art = await bundleMutation.mutateAsync({
          files: v.entries.map((e) => e.file),
          bundleRelativePaths: v.pathsForUpload,
        });
        setBundleArtifact(art);
      } else {
        const data = await batchMutation.mutateAsync(v.entries.map((e) => e.file));
        setBatchResult(data);
      }
    } catch {
      // surfaced via mutation.error
    }
  }

  const uploadError =
    batchMutation.error || bundleMutation.error ? formatApiError(batchMutation.error || bundleMutation.error) : null;

  const singleSuccessArtifact: Artifact | null = useMemo(() => {
    if (!batchResult) return null;
    if (batchResult.summary.ok !== 1 || batchResult.summary.error !== 0) return null;
    const okRows = batchResult.items.filter((x): x is { ok: true; artifact: Artifact } => x.ok);
    if (okRows.length !== 1) return null;
    const only = okRows[0];
    return only ? only.artifact : null;
  }, [batchResult]);

  const resultSuccesses = useMemo(() => {
    if (!batchResult) return [];
    return batchResult.items.filter((x) => x.ok) as Array<{ ok: true; artifact: Artifact }>;
  }, [batchResult]);

  const resultFailures = useMemo(() => {
    if (!batchResult) return [];
    return batchResult.items.filter((x) => !x.ok) as Array<{
      ok: false;
      filename: string;
      code: string;
      message: string;
    }>;
  }, [batchResult]);

  function resetFlow() {
    setBatchResult(null);
    setBundleArtifact(null);
    setPendingEntries([]);
    setStagedEntries([]);
    setSubfolderSelection(null);
    setSelectedSubfolders(new Set());
    setClientError(null);
    setExtensionSkipNotice(null);
    batchMutation.reset();
    bundleMutation.reset();
  }

  const showForm = !batchResult && !bundleArtifact;
  const uploadPending = batchMutation.isPending || bundleMutation.isPending;

  return (
    <section className="sg-page">
      <h1 className="sg-page__title">Upload artifacts</h1>

      {showForm && (
        <form className="sg-form" onSubmit={handleUpload}>
          <fieldset className="sg-form__fieldset" style={{ border: "none", padding: 0, margin: "0 0 1rem" }}>
            <legend className="sg-form__hint" style={{ marginBottom: "0.5rem" }}>
              Upload mode
            </legend>
            <label style={{ marginRight: "1.25rem" }}>
              <input
                type="radio"
                name="uploadLayout"
                checked={uploadLayout === "separate"}
                onChange={() => handleLayoutChange("separate")}
              />{" "}
              Separate artifacts (one scan target per file)
            </label>
            <label>
              <input
                type="radio"
                name="uploadLayout"
                checked={uploadLayout === "combined"}
                onChange={() => handleLayoutChange("combined")}
              />{" "}
              Combined graph (one artifact; graph merges all files in one language)
            </label>
          </fieldset>

          <div
            className={`sg-dropzone${isDragOver ? " sg-dropzone--active" : ""}`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <p className="sg-dropzone__label">
              {uploadLayout === "combined"
                ? "Drop files, or drop a single folder (Chrome/Edge/Safari). Or use Select files / Select folder. Folder uploads preserve relative paths; when the tree has several subfolders you can include only the ones you need."
                : "Drag and drop source files here, or select them (multiple allowed). Each file becomes a separate artifact."}
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", alignItems: "center" }}>
              <label className="sg-button sg-button--ghost" style={{ cursor: "pointer", margin: 0 }}>
                Select files
                <input
                  type="file"
                  multiple
                  onChange={handleFlatFileInput}
                  aria-label="Source files"
                  style={{ display: "none" }}
                />
              </label>
              {uploadLayout === "combined" && (
                <label className="sg-button sg-button--ghost" style={{ cursor: "pointer", margin: 0 }}>
                  Select folder
                  <input
                    type="file"
                    multiple
                    {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
                    onChange={handleFolderFileInput}
                    aria-label="Source folder"
                    style={{ display: "none" }}
                  />
                </label>
              )}
            </div>
            <p className="sg-form__hint">
              Max {MAX_BATCH_FILES} files; {formatSize(MAX_UPLOAD_BYTES)} per file
              {uploadLayout === "combined" ? `; bundle total ${formatSize(MAX_BUNDLE_BYTES_TOTAL)}.` : "."} Only{" "}
              {ALLOWED_EXTENSIONS.join(", ")} are kept; other files are ignored.
            </p>
          </div>

          {clientError && <p className="sg-banner sg-banner--error">{clientError}</p>}

          {extensionSkipNotice && (
            <p className="sg-banner sg-banner--info">{extensionSkipNotice}</p>
          )}

          {subfolderSelection && uploadLayout === "combined" && (
            <div className="sg-subfolder-picker" role="group" aria-label="Subfolders to include">
              <p className="sg-subfolder-picker__title">
                Include subfolders under{" "}
                <span className="sg-preview__value--mono">
                  {subfolderSelection.root || "(root)"}
                </span>
              </p>
              <p className="sg-form__hint">
                {selectedSubfolders.size} of {subfolderSelection.subfolders.length} selected;{" "}
                {stagedEntries.length} file(s) in full folder, {pendingEntries.length} after filter.
              </p>
              <div className="sg-subfolder-picker__actions">
                <button
                  type="button"
                  className="sg-button sg-button--ghost"
                  onClick={handleSubfolderSelectAll}
                >
                  Select all
                </button>
              </div>
              <ul className="sg-subfolder-picker__list">
                {subfolderSelection.subfolders.map((name) => (
                  <li key={name}>
                    <label className="sg-subfolder-picker__label">
                      <input
                        type="checkbox"
                        checked={selectedSubfolders.has(name)}
                        onChange={(event) => handleSubfolderToggle(name, event.target.checked)}
                      />{" "}
                      {name}
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {pendingEntries.length > 0 && (
            <div className="sg-preview">
              <div>
                <span className="sg-preview__label">Files</span>
                <span className="sg-preview__value">{pendingEntries.length} selected</span>
              </div>
              {uploadLayout === "combined" && (
                <div>
                  <span className="sg-preview__label">Bundle layout</span>
                  <span className="sg-preview__value">
                    {combinedUsesTreePaths ? "tree (manifest v2 paths)" : "flat (basenames)"}
                  </span>
                </div>
              )}
              <ul className="sg-form__hint" style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
                {pendingEntries.map((e, i) => (
                  <li
                    key={`${displayPathForEntry(e)}-${e.file.size}-${e.file.lastModified}-${i}`}
                  >
                    {displayPathForEntry(e)} ({formatSize(e.file.size)})
                  </li>
                ))}
              </ul>
              <div>
                <span className="sg-preview__label">Languages (detected)</span>
                <span className="sg-preview__value">{previewLanguages}</span>
              </div>
            </div>
          )}

          {uploadError && <p className="sg-banner sg-banner--error">Upload failed: {uploadError}</p>}

          <button
            type="submit"
            className="sg-button sg-button--primary"
            disabled={pendingEntries.length === 0 || uploadPending}
          >
            {uploadPending
              ? "Uploading..."
              : pendingEntries.length <= 1
                ? "Upload"
                : `Upload ${pendingEntries.length} files`}
          </button>
        </form>
      )}

      {bundleArtifact && (
        <div className="sg-form">
          <p className="sg-form__hint">
            Combined artifact created. Findings are merged; the graph unions per-file models and adds explicit links for C includes, Solidity imports, and Rust module references when they point at other files in the bundle.
          </p>
          <p>
            <Link className="sg-link" to={`/artifacts/${bundleArtifact.id}`}>
              #{bundleArtifact.id} {bundleArtifact.filename}
            </Link>{" "}
            ({bundleArtifact.language})
          </p>
          <RunScanForm
            artifactId={bundleArtifact.id}
            language={bundleArtifact.language}
            defaultMode={defaultRunMode}
            onSuccess={(scan) => {
              saveUploadContextForScan(scan.artifact_id, uploadLayout);
              navigate(`/scans/${scan.id}`);
            }}
          />
          <div className="sg-form__actions">
            <button type="button" className="sg-button" onClick={resetFlow}>
              Upload more files
            </button>
            <Link to="/history" className="sg-button sg-button--ghost">
              History
            </Link>
          </div>
        </div>
      )}

      {batchResult && (
        <div className="sg-form">
          <p className="sg-form__hint">
            Uploaded {batchResult.summary.ok} ok, {batchResult.summary.error} failed.
          </p>

          {resultSuccesses.length > 0 && (
            <div className="sg-preview">
              <span className="sg-preview__label">Artifacts</span>
              <ul className="sg-form__hint" style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
                {resultSuccesses.map((row) => (
                  <li key={`${row.artifact.id}-${row.artifact.filename}`}>
                    <Link to={`/artifacts/${row.artifact.id}`}>
                      #{row.artifact.id} {row.artifact.filename}
                    </Link>{" "}
                    ({row.artifact.language})
                  </li>
                ))}
              </ul>
            </div>
          )}

          {resultFailures.length > 0 && (
            <div className="sg-banner sg-banner--error">
              <strong>Failed</strong>
              <ul style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
                {resultFailures.map((row) => (
                  <li key={row.filename}>
                    {row.filename}: {row.code} — {row.message}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {singleSuccessArtifact && (
            <RunScanForm
              artifactId={singleSuccessArtifact.id}
              language={singleSuccessArtifact.language}
              defaultMode={defaultRunMode}
              onSuccess={(scan) => {
              saveUploadContextForScan(scan.artifact_id, uploadLayout);
              navigate(`/scans/${scan.id}`);
            }}
            />
          )}

          <div className="sg-form__actions">
            <button type="button" className="sg-button" onClick={resetFlow}>
              Upload more files
            </button>
            <Link to="/history" className="sg-button sg-button--ghost">
              History
            </Link>
          </div>
        </div>
      )}
    </section>
  );
}
