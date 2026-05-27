/**
 * Filter folder-shaped bundle uploads to immediate subfolders under a common root.
 */

export type BundleFolderFilterEntry = {
  treePath: string;
};

function splitPath(path: string): string[] {
  return path
    .trim()
    .replace(/\\/g, "/")
    .split("/")
    .filter((seg) => seg.length > 0 && seg !== ".");
}

/** Longest shared prefix of normalized POSIX paths (may be empty). */
export function commonPathPrefix(paths: string[]): string {
  if (paths.length === 0) return "";
  const split = paths.map((p) => splitPath(p));
  const minLen = Math.min(...split.map((s) => s.length));
  const common: string[] = [];
  for (let i = 0; i < minLen; i += 1) {
    const seg = split[0]![i];
    if (split.every((s) => s[i] === seg)) {
      common.push(seg!);
    } else {
      break;
    }
  }
  return common.join("/");
}

export type BundleSubfolderSelection = {
  /** Shared prefix for all staged tree paths (may be empty). */
  root: string;
  /** Immediate child folder names under root that contain at least one file. */
  subfolders: string[];
};

/**
 * When two or more sibling folders exist under root, user can include/exclude them.
 * Returns null if subfolder UI should not be shown.
 */
export function inferBundleSubfolderSelection(paths: string[]): BundleSubfolderSelection | null {
  const normalized = paths.map((p) => splitPath(p).join("/")).filter((p) => p.length > 0);
  if (normalized.length === 0) return null;

  const root = commonPathPrefix(normalized);
  const rootDepth = splitPath(root).length;
  const subs = new Set<string>();

  for (const p of normalized) {
    const parts = splitPath(p);
    // Need at least one directory segment under root plus a file leaf.
    if (parts.length <= rootDepth + 1) continue;
    subs.add(parts[rootDepth]!);
  }

  const subfolders = [...subs].sort();
  if (subfolders.length < 2) return null;

  return { root, subfolders };
}

export function filterEntriesBySubfolders<T extends BundleFolderFilterEntry>(
  entries: T[],
  root: string,
  selectedSubfolders: ReadonlySet<string>,
): T[] {
  const rootDepth = splitPath(root).length;
  return entries.filter((entry) => {
    const parts = splitPath(entry.treePath);
    if (parts.length <= rootDepth) return selectedSubfolders.size === 0;
    return selectedSubfolders.has(parts[rootDepth]!);
  });
}

export function defaultSelectedSubfolders(subfolders: string[]): Set<string> {
  return new Set(subfolders);
}
