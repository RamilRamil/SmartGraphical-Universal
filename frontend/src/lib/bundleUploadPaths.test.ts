import { describe, expect, it } from "vitest";

import {
  coalesceFolderRelativePath,
  entryLeafFileName,
  isAllowedFileName,
  normalizeClientTreePath,
} from "./bundleUploadPaths";

function mockFile(name: string): Pick<File, "name"> {
  return { name };
}

describe("isAllowedFileName", () => {
  it("accepts declared extensions", () => {
    expect(isAllowedFileName("a.sol")).toBe(true);
    expect(isAllowedFileName("b.c")).toBe(true);
    expect(isAllowedFileName("c.h")).toBe(true);
    expect(isAllowedFileName("d.rs")).toBe(true);
  });
  it("rejects directory-like names", () => {
    expect(isAllowedFileName("src")).toBe(false);
    expect(isAllowedFileName("factories")).toBe(false);
  });
});

describe("coalesceFolderRelativePath", () => {
  it("appends File.name when path ends with a directory segment", () => {
    const f = mockFile("Token.sol");
    expect(coalesceFolderRelativePath(f, "src")).toBe("src/Token.sol");
  });
  it("appends for nested directory-only tail", () => {
    const f = mockFile("Lib.sol");
    expect(coalesceFolderRelativePath(f, "contracts/a")).toBe("contracts/a/Lib.sol");
  });
  it("leaves full paths unchanged", () => {
    const f = mockFile("ignored.sol");
    expect(coalesceFolderRelativePath(f, "src/Token.sol")).toBe("src/Token.sol");
  });
  it("returns null for null raw", () => {
    expect(coalesceFolderRelativePath(mockFile("a.sol"), null)).toBeNull();
  });
});

describe("entryLeafFileName", () => {
  it("uses File.name when treePath is a single folder segment", () => {
    const entry = { file: mockFile("Token.sol"), treePath: "src" };
    expect(entryLeafFileName(entry)).toBe("Token.sol");
  });
  it("prefers path leaf when it has a source extension", () => {
    const entry = { file: mockFile("wrong.bin"), treePath: "src/Token.sol" };
    expect(entryLeafFileName(entry)).toBe("Token.sol");
  });
  it("handles factories-style segment with real name on File", () => {
    const entry = { file: mockFile("Pair.sol"), treePath: "factories" };
    expect(entryLeafFileName(entry)).toBe("Pair.sol");
  });
});

describe("normalizeClientTreePath", () => {
  it("normalizes coalesced paths for bundle upload", () => {
    const r = normalizeClientTreePath("src/Token.sol");
    expect(r).toEqual({ ok: true, path: "src/Token.sol" });
  });
  it("rejects parent segments", () => {
    const r = normalizeClientTreePath("a/../b.sol");
    expect(r.ok).toBe(false);
  });
});
