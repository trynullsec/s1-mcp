export const severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export const categories = [
  "auth",
  "secrets",
  "input_validation",
  "rate_limits",
  "dangerous_exec",
  "dependency_risk",
  "environment_exposure",
  "permissions",
  "web3_base"
] as const;
export const confidences = ["LOW", "MEDIUM", "HIGH"] as const;

export type Severity = (typeof severities)[number];
export type FindingCategory = (typeof categories)[number];
export type Confidence = (typeof confidences)[number];
export type GateVerdict = "pass" | "warn" | "block";

export type PatchSuggestion = {
  summary: string;
  steps: string[];
};

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  file: string;
  line?: number;
  evidence?: string;
  explanation: string;
  exploitScenario: string;
  recommendation: string;
  productionBlocker: boolean;
  confidence: Confidence;
  patchSuggestion?: PatchSuggestion;
};

export type UnsupportedScanResult = {
  unsupported: true;
  reason: string;
};

export type ProductionGate = {
  verdict: GateVerdict;
  reason: string;
  blockedBy: string[];
};

export type SeveritySummary = Record<Severity, number>;

export type ScanResult = {
  target: string;
  filesScanned: number;
  rulesExecuted: number;
  summary: SeveritySummary;
  issues: Finding[];
  productionGate: ProductionGate;
  unsupported?: UnsupportedScanResult;
};

export type ScanOptions = {
  ruleCategories?: FindingCategory[];
};

export type GatePolicy = {
  blockCritical: boolean;
  blockHigh: boolean;
  requireDimensions?: FindingCategory[];
};

export type GateResult = {
  verdict: GateVerdict;
  riskScore: number;
  blockers: Finding[];
  missingDimensions: FindingCategory[];
  recommendation: string;
};

export type ExplanationAudience = "developer" | "founder" | "auditor";
