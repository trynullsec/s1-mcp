import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { scanFile, scanRepo } from "../src/scanner/scan.js";

let tmpRoot: string;
let originalCwd: string;

beforeEach(async () => {
  originalCwd = process.cwd();
  tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "s1-mcp-scan-"));
  process.chdir(tmpRoot);
});

afterEach(async () => {
  process.chdir(originalCwd);
  await fs.rm(tmpRoot, { recursive: true, force: true });
});

describe("general app scanner", () => {
  it("detects vulnerable Next.js admin route findings", async () => {
    const routePath = path.join(tmpRoot, "app/api/admin/route.ts");
    await fs.mkdir(path.dirname(routePath), { recursive: true });
    await fs.writeFile(
      routePath,
      `import { NextResponse } from "next/server";
import { exec } from "child_process";

export async function POST(req: Request) {
  const body = await req.json();

  const apiKey = "sk_live_SUPER_SECRET_KEY_DO_NOT_USE";
  const command = body.command;

  exec(command, (error, stdout, stderr) => {
    console.log({ error, stdout, stderr });
  });

  return NextResponse.json({
    ok: true,
    admin: true,
    apiKey,
  });
}
`
    );

    const result = await scanRepo({ target: "." });
    const ids = new Set(result.issues.map((issue) => issue.id));

    expect(result.filesScanned).toBe(1);
    expect(ids).toContain("S1-EXEC-005");
    expect(ids).toContain("S1-SEC-001");
    expect(ids).toContain("S1-AUTH-001");
    expect(ids).toContain("S1-VAL-001");
    expect(ids).toContain("S1-RATE-001");
    expect(result.issues.find((issue) => issue.id === "S1-EXEC-005")?.severity).toBe("CRITICAL");
    expect(result.issues.find((issue) => issue.id === "S1-SEC-001")?.severity).toBe("CRITICAL");
    expect(result.issues.find((issue) => issue.id === "S1-AUTH-001")?.severity).toBe("HIGH");
    expect(result.issues.find((issue) => issue.id === "S1-VAL-001")?.severity).toBe("MEDIUM");
    expect(result.issues.find((issue) => issue.id === "S1-RATE-001")?.severity).toBe("MEDIUM");
    expect(result.productionGate.verdict).toBe("block");
  });

  it("returns unsupported for an unsupported file without calling it secure", async () => {
    await fs.writeFile(path.join(tmpRoot, "notes.md"), "# Notes\n");
    const result = await scanFile({ filePath: "notes.md" });

    expect(result.filesScanned).toBe(0);
    expect(result.unsupported?.unsupported).toBe(true);
    expect(result.unsupported?.reason).toContain("Unsupported file extension");
    expect(result.productionGate.reason).not.toMatch(/secure/i);
  });

  it("scans one TypeScript file", async () => {
    await fs.writeFile(path.join(tmpRoot, "route.ts"), "export async function POST(req: Request) { await req.json(); }\n");
    const result = await scanFile({ filePath: "route.ts" });

    expect(result.filesScanned).toBe(1);
    expect(result.issues.some((issue) => issue.id === "S1-VAL-001")).toBe(true);
  });

  it("returns unsupported repo result when no supported files are found", async () => {
    await fs.writeFile(path.join(tmpRoot, "README.md"), "hello\n");
    const result = await scanRepo({ target: "." });

    expect(result.filesScanned).toBe(0);
    expect(result.unsupported?.reason).toContain("not a secure/pass result");
  });
});
