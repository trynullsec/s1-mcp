import { describe, expect, it } from "vitest";

import {
  S1ScanRepoInputSchema,
  S1ZkExplainInputSchema,
  S1ZkRulesInputSchema,
  S1ZkScanInputSchema
} from "../src/types.js";

describe("tool input validation", () => {
  it("defaults scan deep to false and format to json", () => {
    expect(S1ZkScanInputSchema.parse({ target: "circuits" })).toEqual({
      target: "circuits",
      deep: false,
      format: "json"
    });
  });

  it("rejects unsupported scan formats", () => {
    expect(() =>
      S1ZkScanInputSchema.parse({ target: "circuits", format: "text" })
    ).toThrow();
  });

  it("requires a rule ID for explain", () => {
    expect(() => S1ZkExplainInputSchema.parse({})).toThrow();
  });

  it("accepts empty rules input", () => {
    expect(S1ZkRulesInputSchema.parse({})).toEqual({});
  });

  it("requires a target for the repo scan placeholder", () => {
    expect(() => S1ScanRepoInputSchema.parse({})).toThrow();
  });
});
