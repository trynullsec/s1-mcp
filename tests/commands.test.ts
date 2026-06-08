import { describe, expect, it } from "vitest";

import { buildS1ZkExplainCommand } from "../src/tools/s1-zk-explain.js";
import { buildS1ZkRulesCommand } from "../src/tools/s1-zk-rules.js";
import { buildS1ZkScanCommand } from "../src/tools/s1-zk-scan.js";

describe("command builders", () => {
  it("builds the s1-zk scan command with argv only", () => {
    const command = buildS1ZkScanCommand({
      target: "circuits",
      deep: true,
      format: "json"
    });

    expect(command.command).toBe("npx");
    expect(command.args).toEqual([
      "-y",
      "@trynullsec/s1-zk",
      "scan",
      expect.stringContaining("circuits"),
      "--format",
      "json",
      "--no-banner",
      "--deep"
    ]);
  });

  it("omits --deep when deep is false", () => {
    const command = buildS1ZkScanCommand({
      target: "circuits",
      deep: false,
      format: "json"
    });

    expect(command.args).not.toContain("--deep");
  });

  it("builds the explain command", () => {
    expect(buildS1ZkExplainCommand({ ruleId: "NS-H2-005" })).toEqual({
      command: "npx",
      args: ["-y", "@trynullsec/s1-zk", "explain", "NS-H2-005", "--no-banner"]
    });
  });

  it("builds the rules command", () => {
    expect(buildS1ZkRulesCommand()).toEqual({
      command: "npx",
      args: ["-y", "@trynullsec/s1-zk", "rules", "--no-banner"]
    });
  });
});
