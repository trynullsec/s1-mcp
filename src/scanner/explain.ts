import type { ExplanationAudience, Finding } from "./types.js";

const fallbackExplanations: Record<string, Omit<Finding, "file">> = {
  "S1-EXEC-005": {
    id: "S1-EXEC-005",
    title: "User input reaches command execution",
    severity: "CRITICAL",
    category: "dangerous_exec",
    explanation: "Request-controlled input appears to flow into command execution.",
    exploitScenario: "A caller can submit shell metacharacters or a full command and execute arbitrary code on the server.",
    recommendation: "Remove request-controlled command execution and replace it with explicit server-side actions.",
    productionBlocker: true,
    confidence: "HIGH"
  },
  "S1-SEC-001": {
    id: "S1-SEC-001",
    title: "Hardcoded live secret key",
    severity: "CRITICAL",
    category: "secrets",
    explanation: "A live secret key is embedded directly in source code.",
    exploitScenario: "An attacker with source or response access can use the live key against the upstream service.",
    recommendation: "Revoke the exposed key, move it to a secret manager or environment variable, and never return it in responses.",
    productionBlocker: true,
    confidence: "HIGH"
  },
  "S1-AUTH-001": {
    id: "S1-AUTH-001",
    title: "Admin API route without visible authorization",
    severity: "HIGH",
    category: "auth",
    explanation: "An admin API handler does not show an obvious session, role, or permission check.",
    exploitScenario: "An unauthenticated caller can reach admin-only behavior or observe admin-only response fields.",
    recommendation: "Require authentication and an explicit admin role or permission check before executing handler logic.",
    productionBlocker: true,
    confidence: "HIGH"
  }
};

export function explainFinding(
  input: { findingId: string } | { finding: Finding },
  audience: ExplanationAudience = "developer"
): string {
  const finding = "finding" in input ? input.finding : fallbackFinding(input.findingId);
  const prefix = audiencePrefix(audience, finding);

  return [
    prefix,
    "",
    `What it means: ${finding.explanation}`,
    `Why it matters: ${finding.severity} ${finding.category} findings can create real production risk when shipped unreviewed.`,
    `Exploit scenario: ${finding.exploitScenario}`,
    `Fix: ${finding.recommendation}`,
    `Production gate: ${finding.productionBlocker ? "Block production until fixed." : "Review before production; blocking depends on policy."}`
  ].join("\n");
}

function fallbackFinding(id: string): Finding {
  const fallback = fallbackExplanations[id];
  if (fallback !== undefined) {
    return {
      ...fallback,
      file: "unknown"
    };
  }

  return {
    id,
    title: "Unknown deterministic S1 finding",
    severity: "INFO",
    category: "input_validation",
    file: "unknown",
    explanation: "This finding id is not in the local explanation catalog. Pass the full finding object for a precise explanation.",
    exploitScenario: "Unknown without the full finding context.",
    recommendation: "Re-run the scanner and pass the complete finding object to s1_explain_finding.",
    productionBlocker: false,
    confidence: "LOW"
  };
}

function audiencePrefix(audience: ExplanationAudience, finding: Finding): string {
  switch (audience) {
    case "founder":
      return `${finding.title}: this is a ${finding.severity.toLowerCase()} launch risk in ${finding.file}.`;
    case "auditor":
      return `${finding.id} (${finding.severity}, ${finding.category}) in ${finding.file}. Confidence: ${finding.confidence}.`;
    case "developer":
      return `${finding.id}: ${finding.title} in ${finding.file}.`;
  }
}
