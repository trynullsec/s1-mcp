import { describe, expect, it } from "vitest";

import {
  S1ExplainFindingInputSchema,
  S1GateInputSchema,
  S1ScanFileInputSchema,
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

  it("requires a target for the repo scan", () => {
    expect(() => S1ScanRepoInputSchema.parse({})).toThrow();
  });

  it("requires a file path for single file scan", () => {
    expect(() => S1ScanFileInputSchema.parse({})).toThrow();
  });

  it("requires finding id or finding object for explanations", () => {
    expect(() => S1ExplainFindingInputSchema.parse({})).toThrow();
    expect(S1ExplainFindingInputSchema.parse({ findingId: "S1-SEC-001" }).audience).toBe("developer");
  });

  it("requires target or findings for production gate", () => {
    expect(() => S1GateInputSchema.parse({})).toThrow();
    expect(S1GateInputSchema.parse({ target: "." }).policy).toEqual({
      blockCritical: true,
      blockHigh: true
    });
  });
});
