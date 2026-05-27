import { describe, expect, it } from "vitest";

import {
  commonPathPrefix,
  filterEntriesBySubfolders,
  inferBundleSubfolderSelection,
} from "./bundleFolderFilter";

describe("commonPathPrefix", () => {
  it("returns shared directory prefix", () => {
    expect(
      commonPathPrefix([
        "contracts/vault/A.sol",
        "contracts/oracle/B.sol",
        "contracts/utils/C.sol",
      ]),
    ).toBe("contracts");
  });

  it("returns empty when paths diverge at top level", () => {
    expect(commonPathPrefix(["vault/A.sol", "oracle/B.sol"])).toBe("");
  });
});

describe("inferBundleSubfolderSelection", () => {
  it("lists immediate subfolders under common root", () => {
    const sel = inferBundleSubfolderSelection([
      "contracts/vault/A.sol",
      "contracts/oracle/B.sol",
      "contracts/utils/C.sol",
    ]);
    expect(sel).toEqual({
      root: "contracts",
      subfolders: ["oracle", "utils", "vault"],
    });
  });

  it("returns null for single subfolder tree", () => {
    expect(
      inferBundleSubfolderSelection(["contracts/vault/A.sol", "contracts/vault/B.sol"]),
    ).toBeNull();
  });

  it("returns null for flat paths at root", () => {
    expect(inferBundleSubfolderSelection(["A.sol", "B.sol"])).toBeNull();
  });
});

describe("filterEntriesBySubfolders", () => {
  const entries = [
    { treePath: "contracts/vault/A.sol" },
    { treePath: "contracts/oracle/B.sol" },
    { treePath: "contracts/utils/C.sol" },
  ];

  it("keeps only files under selected subfolders", () => {
    const out = filterEntriesBySubfolders(entries, "contracts", new Set(["vault", "oracle"]));
    expect(out.map((e) => e.treePath)).toEqual([
      "contracts/vault/A.sol",
      "contracts/oracle/B.sol",
    ]);
  });

  it("includes nested files under a selected subfolder", () => {
    const nested = [
      { treePath: "contracts/vault/modules/X.sol" },
      { treePath: "contracts/oracle/B.sol" },
    ];
    const out = filterEntriesBySubfolders(nested, "contracts", new Set(["vault"]));
    expect(out).toHaveLength(1);
    expect(out[0]?.treePath).toBe("contracts/vault/modules/X.sol");
  });
});
