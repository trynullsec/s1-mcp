import { z } from "zod";

const FindingSeveritySchema = z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const FindingCategorySchema = z.enum([
  "auth",
  "secrets",
  "input_validation",
  "rate_limits",
  "dangerous_exec",
  "dependency_risk",
  "environment_exposure",
  "permissions",
  "web3_base"
]);
const FindingConfidenceSchema = z.enum(["LOW", "MEDIUM", "HIGH"]);

const FindingSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  severity: FindingSeveritySchema,
  category: FindingCategorySchema,
  file: z.string().min(1),
  line: z.number().int().positive().optional(),
  evidence: z.string().optional(),
  explanation: z.string().min(1),
  exploitScenario: z.string().min(1),
  recommendation: z.string().min(1),
  productionBlocker: z.boolean(),
  confidence: FindingConfidenceSchema
}).passthrough();

export const S1ZkScanInputSchema = z.object({
  target: z.string().min(1),
  deep: z.boolean().optional().default(false),
  format: z.literal("json").optional().default("json")
}).strict();

export const S1ZkExplainInputSchema = z.object({
  ruleId: z.string().min(1)
}).strict();

export const S1ZkRulesInputSchema = z.object({}).strict();

export const S1ScanRepoInputSchema = z.object({
  target: z.string().min(1),
  ruleCategories: z.array(FindingCategorySchema).optional()
}).strict();

export const S1ScanFileInputSchema = z.object({
  filePath: z.string().min(1),
  ruleCategories: z.array(FindingCategorySchema).optional()
}).strict();

export const S1ExplainFindingInputSchema = z.object({
  findingId: z.string().min(1).optional(),
  finding: FindingSchema.optional(),
  audience: z.enum(["developer", "founder", "auditor"]).optional().default("developer")
}).strict().refine((input) => input.findingId !== undefined || input.finding !== undefined, {
  message: "findingId or finding is required"
});

export const S1GateInputSchema = z.object({
  target: z.string().min(1).optional(),
  findings: z.array(FindingSchema).optional(),
  policy: z.object({
    blockCritical: z.boolean().optional().default(true),
    blockHigh: z.boolean().optional().default(true),
    requireDimensions: z.array(FindingCategorySchema).optional()
  }).optional().default({})
}).strict().refine((input) => input.target !== undefined || input.findings !== undefined, {
  message: "target or findings is required"
});

export type S1ZkScanInput = z.infer<typeof S1ZkScanInputSchema>;
export type S1ZkExplainInput = z.infer<typeof S1ZkExplainInputSchema>;
export type S1ZkRulesInput = z.infer<typeof S1ZkRulesInputSchema>;
export type S1ScanRepoInput = z.infer<typeof S1ScanRepoInputSchema>;
export type S1ScanFileInput = z.infer<typeof S1ScanFileInputSchema>;
export type S1ExplainFindingInput = z.infer<typeof S1ExplainFindingInputSchema>;
export type S1GateInput = z.infer<typeof S1GateInputSchema>;
