/**
 * Paths and extension checks for combined (folder-shaped) bundle uploads.
 * Kept free of React so behavior can be unit-tested without a browser.
 */

export const BUNDLE_REL_MAX_LEN = 512;
export const BUNDLE_REL_MAX_PARTS = 64;
export const ALLOWED_EXTENSIONS = [".sol", ".c", ".h", ".rs"] as const;

export type BundlePendingEntry = {
  file: Pick<File, "name">;
  treePath: string | null;
};

export function readWebkitRelativePath(file: File): string | null {
  const w = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
  if (typeof w !== "string" || w.length === 0) return null;
  return w;
}

export function isAllowedFileName(name: string): boolean {
  const lower = name.toLowerCase();
  return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * When the browser gives only a directory segment as the relative path (e.g. "src")
 * while File.name is the real "Foo.sol", append the file name for validation and
 * bundle_paths_json.
 */
export function coalesceFolderRelativePath(file: Pick<File, "name">, raw: string | null): string | null {
  if (raw === null) return null;
  const s = raw.trim().replace(/\\/g, "/");
  if (!s) return null;
  const segs = s.split("/").filter((seg) => seg.length > 0 && seg !== ".");
  if (segs.length === 0) return null;
  const last = segs[segs.length - 1]!;
  if (isAllowedFileName(last)) {
    return segs.join("/");
  }
  const rawFile = file.name.replace(/\\/g, "/");
  const fileLeaf = rawFile.includes("/")
    ? rawFile.split("/").filter((x) => x.length > 0).pop() ?? rawFile
    : rawFile;
  if (isAllowedFileName(fileLeaf)) {
    return `${segs.join("/")}/${fileLeaf}`;
  }
  return segs.join("/");
}

/** Leaf filename for extension / language checks (handles bogus File.name or one-segment treePath). */
export function entryLeafFileName(entry: BundlePendingEntry): string {
  const rawTree = entry.treePath;
  let treeLeaf: string | null = null;
  if (rawTree) {
    const parts = rawTree
      .replace(/\\/g, "/")
      .split("/")
      .filter((s) => s.length > 0);
    if (parts.length > 0) {
      treeLeaf = parts[parts.length - 1] ?? null;
    }
  }

  const rawFile = entry.file.name.replace(/\\/g, "/");
  const fileLeaf = rawFile.includes("/")
    ? rawFile.split("/").filter((s) => s.length > 0).pop() ?? rawFile
    : rawFile;

  if (treeLeaf && isAllowedFileName(treeLeaf)) {
    return treeLeaf;
  }
  if (isAllowedFileName(fileLeaf)) {
    return fileLeaf;
  }
  return treeLeaf ?? fileLeaf;
}

export function normalizeClientTreePath(
  raw: string,
): { ok: true; path: string } | { ok: false; error: string } {
  const s = raw.trim().replace(/\\/g, "/");
  if (!s || s.includes("\0")) {
    return { ok: false, error: "Invalid path." };
  }
  if (s.length > BUNDLE_REL_MAX_LEN) {
    return { ok: false, error: `Path exceeds ${BUNDLE_REL_MAX_LEN} characters.` };
  }
  if (s.startsWith("/") || /^[a-zA-Z]:/.test(s)) {
    return { ok: false, error: "Path must be relative (no absolute paths)." };
  }
  const parts: string[] = [];
  for (const seg of s.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      return { ok: false, error: "Path must not contain parent segments (..)." };
    }
    parts.push(seg);
  }
  if (parts.length === 0) {
    return { ok: false, error: "Path is empty after normalization." };
  }
  if (parts.length > BUNDLE_REL_MAX_PARTS) {
    return { ok: false, error: `Path has more than ${BUNDLE_REL_MAX_PARTS} segments.` };
  }
  return { ok: true, path: parts.join("/") };
}
