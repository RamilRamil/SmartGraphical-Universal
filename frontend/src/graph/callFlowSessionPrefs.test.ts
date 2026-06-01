import { describe, expect, it } from "vitest";

import {
  defaultCallFlowSessionPrefs,
  parseCallFlowSessionPrefs,
} from "./callFlowSessionPrefs";

describe("callFlowSessionPrefs", () => {
  it("parses valid prefs", () => {
    const raw = JSON.stringify({
      direction: "downstream",
      depth: 3,
      depthMode: "full",
      showExternalCalls: false,
    });
    expect(parseCallFlowSessionPrefs(raw)).toEqual({
      direction: "downstream",
      depth: 3,
      depthMode: "full",
      showExternalCalls: false,
    });
  });

  it("rejects invalid direction or depth", () => {
    expect(
      parseCallFlowSessionPrefs(
        JSON.stringify({
          direction: "sideways",
          depth: 2,
          depthMode: "limited",
          showExternalCalls: true,
        }),
      ),
    ).toBeNull();
    expect(
      parseCallFlowSessionPrefs(
        JSON.stringify({
          direction: "both",
          depth: 5,
          depthMode: "limited",
          showExternalCalls: true,
        }),
      ),
    ).toBeNull();
  });

  it("default prefs match product defaults", () => {
    expect(defaultCallFlowSessionPrefs()).toEqual({
      direction: "both",
      depth: 2,
      depthMode: "limited",
      showExternalCalls: true,
    });
  });
});
