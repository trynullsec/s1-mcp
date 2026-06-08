import { z } from "zod";

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
  target: z.string().min(1)
}).strict();

export type S1ZkScanInput = z.infer<typeof S1ZkScanInputSchema>;
export type S1ZkExplainInput = z.infer<typeof S1ZkExplainInputSchema>;
export type S1ZkRulesInput = z.infer<typeof S1ZkRulesInputSchema>;
export type S1ScanRepoInput = z.infer<typeof S1ScanRepoInputSchema>;
