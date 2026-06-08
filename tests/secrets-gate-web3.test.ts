import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { scanFile, scanRepo } from "../src/scanner/scan.js";
import { evaluateGate } from "../src/scanner/utils.js";
import type { Finding } from "../src/scanner/types.js";

let tmpRoot: string;
let originalCwd: string;

beforeEach(async () => {
  originalCwd = process.cwd();
  tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "s1-mcp-risk-"));
  process.chdir(tmpRoot);
});

afterEach(async () => {
  process.chdir(originalCwd);
  await fs.rm(tmpRoot, { recursive: true, force: true });
});

describe("secrets and evidence handling", () => {
  it("detects sk_live secrets and redacts evidence", async () => {
    const stripePrefix = ["sk", "live"].join("_") + "_";
    const fakeStripeKey = `${stripePrefix}abcdefghijklmnopqrstuvwxyz123456`;
    await fs.writeFile(path.join(tmpRoot, "secret.ts"), `const key = "${fakeStripeKey}";\n`);
    const result = await scanFile({ filePath: "secret.ts" });
    const finding = result.issues.find((issue) => issue.id === "S1-SEC-001");

    expect(finding).toBeDefined();
    expect(finding?.evidence).toContain("sk_live_...redacted");
    expect(finding?.evidence).not.toContain("abcdefghijklmnopqrstuvwxyz");
  });

  it("masks private keys in evidence", async () => {
    await fs.writeFile(
      path.join(tmpRoot, "deploy.ts"),
      'const PRIVATE_KEY = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";\n'
    );
    const result = await scanFile({ filePath: "deploy.ts" });

    expect(result.issues.some((issue) => issue.evidence?.includes("0x...redacted"))).toBe(true);
    expect(JSON.stringify(result)).not.toContain("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  });
});

describe("production gate", () => {
  const baseFinding: Finding = {
    id: "TEST",
    title: "Test finding",
    severity: "MEDIUM",
    category: "input_validation",
    file: "route.ts",
    explanation: "test",
    exploitScenario: "test",
    recommendation: "test",
    productionBlocker: false,
    confidence: "HIGH"
  };

  it("blocks critical findings", () => {
    expect(evaluateGate([{ ...baseFinding, severity: "CRITICAL" }]).verdict).toBe("block");
  });

  it("blocks high findings by default", () => {
    expect(evaluateGate([{ ...baseFinding, severity: "HIGH" }]).verdict).toBe("block");
  });

  it("warns on medium-only findings", () => {
    expect(evaluateGate([baseFinding]).verdict).toBe("warn");
  });
});

describe("Base/EVM scanner rules", () => {
  it("detects tx.origin and delegatecall without Solana wording", async () => {
    await fs.writeFile(
      path.join(tmpRoot, "Vault.sol"),
      `contract Vault {
  function a(address target) public {
    require(tx.origin == msg.sender);
    target.delegatecall("");
  }
}
`
    );
    const result = await scanRepo({ target: "." });
    const text = JSON.stringify(result);

    expect(result.issues.some((issue) => issue.id === "S1-EVM-001")).toBe(true);
    expect(result.issues.some((issue) => issue.id === "S1-EVM-002")).toBe(true);
    expect(text).not.toMatch(/solana/i);
  });

  it("detects private key deploy script", async () => {
    await fs.writeFile(
      path.join(tmpRoot, "deploy.ts"),
      'const PRIVATE_KEY = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";\n'
    );
    const result = await scanRepo({ target: "." });

    expect(result.issues.some((issue) => issue.id === "S1-EVM-007")).toBe(true);
    expect(result.productionGate.verdict).toBe("block");
  });
});
