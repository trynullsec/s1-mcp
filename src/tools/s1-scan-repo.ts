import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { S1ScanRepoInputSchema } from "../types.js";
import { validateTargetPath } from "../utils/path-safety.js";

export const s1ScanRepoTool = {
  name: "s1_scan_repo",
  description: "Placeholder for future general Nullsec S1 repo scan.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Path to the repository to scan."
      }
    },
    required: ["target"],
    additionalProperties: false
  }
} as const;

export async function handleS1ScanRepo(input: unknown): Promise<CallToolResult> {
  const parsedInput = S1ScanRepoInputSchema.parse(input);
  validateTargetPath(parsedInput.target);

  return {
    content: [
      {
        type: "text",
        text: "Not implemented yet. Use s1_zk_scan for Circom/Halo2 circuits."
      }
    ]
  };
}
