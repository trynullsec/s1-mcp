import fs from "node:fs/promises";
import path from "node:path";

import type {
  Finding,
  FindingCategory,
  GatePolicy,
  GateResult,
  GateVerdict,
  ProductionGate,
  ScanResult,
  Severity,
  SeveritySummary
} from "./types.js";
import { severities } from "./types.js";

const supportedExtensions = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".sol"
]);

const ignoredDirectories = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage"
]);

const ignoredFiles = new Set(["pnpm-lock.yaml", "yarn.lock"]);
const generatedJsonFiles = new Set(["package-lock.json"]);

export const RULES_EXECUTED = 29;

export function emptySummary(): SeveritySummary {
  return {
    INFO: 0,
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0
  };
}

export function summarizeFindings(findings: Finding[]): SeveritySummary {
  const summary = emptySummary();
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return summary;
}

export function relativeFile(root: string, filePath: string): string {
  const relative = path.relative(root, filePath);
  return relative.length === 0 ? path.basename(filePath) : relative;
}

export function isSupportedFile(filePath: string): boolean {
  if (path.basename(filePath) === ".env.example") {
    return true;
  }

  return supportedExtensions.has(path.extname(filePath));
}

export function shouldIgnoreFile(filePath: string): boolean {
  const basename = path.basename(filePath);
  return ignoredFiles.has(basename) || generatedJsonFiles.has(basename);
}

export function isEnvFile(filePath: string): boolean {
  const basename = path.basename(filePath);
  return basename === ".env" || basename.startsWith(".env.");
}

export function isEnvExample(filePath: string): boolean {
  return path.basename(filePath) === ".env.example";
}

export async function discoverSupportedFiles(target: string): Promise<string[]> {
  const stat = await fs.stat(target);
  if (stat.isFile()) {
    return isSupportedFile(target) && !shouldIgnoreFile(target) ? [target] : [];
  }

  if (!stat.isDirectory()) {
    return [];
  }

  const files: string[] = [];

  async function visit(directory: string): Promise<void> {
    const entries = await fs.readdir(directory, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) {
          await visit(fullPath);
        }
        continue;
      }

      if (entry.isFile() && isSupportedFile(fullPath) && !shouldIgnoreFile(fullPath)) {
        files.push(fullPath);
      }
    }
  }

  await visit(target);
  return files.sort();
}

export function lineNumberForIndex(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

export function sanitizeEvidence(evidence: string): string {
  let sanitized = evidence;
  sanitized = sanitized.replace(/sk_live_[A-Za-z0-9_=-]+/g, "sk_live_...redacted");
  sanitized = sanitized.replace(/sk_test_[A-Za-z0-9_=-]+/g, "sk_test_...redacted");
  sanitized = sanitized.replace(/(?:sk-ant-|sk-proj-|sk-)[A-Za-z0-9_-]{12,}/g, "sk_...redacted");
  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9._~+/=-]{10,}/gi, "Bearer ...redacted");
  sanitized = sanitized.replace(/([A-Za-z0-9_]*SECRET[A-Za-z0-9_]*\s*[:=]\s*["']?)[^"',\n\s]+/gi, "$1...redacted");
  sanitized = sanitized.replace(/([A-Za-z0-9_]*KEY[A-Za-z0-9_]*\s*[:=]\s*["']?)[^"',\n\s]+/gi, "$1...redacted");
  sanitized = sanitized.replace(/([A-Za-z0-9_]*TOKEN[A-Za-z0-9_]*\s*[:=]\s*["']?)[^"',\n\s]+/gi, "$1...redacted");
  sanitized = sanitized.replace(/([A-Za-z0-9_]*DATABASE_URL\s*[:=]\s*["']?)[^"',\n\s]+/gi, "$1...redacted");
  sanitized = sanitized.replace(/0x[a-fA-F0-9]{64}/g, "0x...redacted");
  sanitized = sanitized.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "-----BEGIN PRIVATE KEY-----...redacted");

  return sanitized.length > 220 ? `${sanitized.slice(0, 217)}...` : sanitized;
}

export function makeFinding(input: Omit<Finding, "evidence"> & { evidence?: string }): Finding {
  return {
    ...input,
    evidence: input.evidence === undefined ? undefined : sanitizeEvidence(input.evidence)
  };
}

export function filterByCategory(findings: Finding[], categories?: FindingCategory[]): Finding[] {
  if (categories === undefined || categories.length === 0) {
    return findings;
  }

  const allowed = new Set(categories);
  return findings.filter((finding) => allowed.has(finding.category));
}

function severityScore(severity: Severity): number {
  switch (severity) {
    case "CRITICAL":
      return 100;
    case "HIGH":
      return 70;
    case "MEDIUM":
      return 35;
    case "LOW":
      return 10;
    case "INFO":
      return 1;
  }
}

export function calculateRiskScore(findings: Finding[]): number {
  return Math.min(100, findings.reduce((total, finding) => total + severityScore(finding.severity), 0));
}

export function evaluateGate(
  findings: Finding[],
  policy: GatePolicy = { blockCritical: true, blockHigh: true }
): GateResult {
  const blockers = findings.filter((finding) => {
    if (finding.severity === "CRITICAL" && policy.blockCritical) {
      return true;
    }

    if (finding.severity === "HIGH" && policy.blockHigh) {
      return true;
    }

    if (finding.productionBlocker) {
      return true;
    }

    return false;
  });

  const presentCategories = new Set(findings.map((finding) => finding.category));
  const missingDimensions = (policy.requireDimensions ?? []).filter(
    (category) => !presentCategories.has(category)
  );

  let verdict: GateVerdict = "pass";
  if (blockers.length > 0) {
    verdict = "block";
  } else if (findings.some((finding) => finding.severity === "MEDIUM" || finding.severity === "LOW")) {
    verdict = "warn";
  }

  if (verdict !== "block" && missingDimensions.length > 0) {
    verdict = "warn";
  }

  return {
    verdict,
    riskScore: calculateRiskScore(findings),
    blockers,
    missingDimensions,
    recommendation: gateRecommendation(verdict, blockers, missingDimensions)
  };
}

export function productionGateFor(findings: Finding[]): ProductionGate {
  const gate = evaluateGate(findings);
  return {
    verdict: gate.verdict,
    reason:
      gate.verdict === "block"
        ? `${gate.blockers.length} production blocker(s) found.`
        : gate.verdict === "warn"
          ? "No blocking issues found, but review warnings before production."
          : "No deterministic production blockers found in supported files.",
    blockedBy: gate.blockers.map((finding) => finding.id)
  };
}

export function makeScanResult(
  target: string,
  filesScanned: number,
  issues: Finding[],
  unsupportedReason?: string
): ScanResult {
  return {
    target,
    filesScanned,
    rulesExecuted: RULES_EXECUTED,
    summary: summarizeFindings(issues),
    issues,
    productionGate: productionGateFor(issues),
    unsupported:
      unsupportedReason === undefined
        ? undefined
        : {
            unsupported: true,
            reason: unsupportedReason
          }
  };
}

function gateRecommendation(
  verdict: GateVerdict,
  blockers: Finding[],
  missingDimensions: FindingCategory[]
): string {
  if (verdict === "block") {
    return `Do not ship until production blockers are fixed: ${blockers
      .map((finding) => finding.title)
      .join("; ")}.`;
  }

  if (missingDimensions.length > 0) {
    return `Review missing required dimensions before release: ${missingDimensions.join(", ")}.`;
  }

  if (verdict === "warn") {
    return "Review and fix medium/low risk findings before production when feasible.";
  }

  return "No deterministic blockers were found in supported files.";
}
