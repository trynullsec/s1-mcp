import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { explainFinding } from "../scanner/explain.js";
import { S1ExplainFindingInputSchema } from "../types.js";

export const s1ExplainFindingTool = {
  name: "s1_explain_finding",
  description:
    "Explain a deterministic Nullsec S1 finding for a developer, founder, or auditor. No LLM or hosted API is required.",
  inputSchema: {
    type: "object",
    properties: {
      findingId: {
        type: "string",
        description: "Known finding id, for example S1-EXEC-005."
      },
      finding: {
        type: "object",
        description: "Full finding object returned by s1_scan_repo or s1_scan_file."
      },
      audience: {
        type: "string",
        enum: ["developer", "founder", "auditor"],
        description: "Explanation audience."
      }
    },
    additionalProperties: false
  }
} as const;

export async function handleS1ExplainFinding(input: unknown): Promise<CallToolResult> {
  const parsedInput = S1ExplainFindingInputSchema.parse(input);
  const explanation =
    parsedInput.finding !== undefined
      ? explainFinding({ finding: parsedInput.finding }, parsedInput.audience)
      : explainFinding({ findingId: parsedInput.findingId ?? "" }, parsedInput.audience);

  return {
    content: [
      {
        type: "text",
        text: explanation
      }
    ]
  };
}
