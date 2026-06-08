import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { scanFile } from "../scanner/scan.js";
import { S1ScanFileInputSchema } from "../types.js";

export const s1ScanFileTool = {
  name: "s1_scan_file",
  description:
    "Scan one supported application/security file with deterministic Nullsec S1 rules. Unsupported files return an explicit unsupported result.",
  inputSchema: {
    type: "object",
    properties: {
      filePath: {
        type: "string",
        description: "Path to the file to scan."
      },
      ruleCategories: {
        type: "array",
        items: {
          type: "string",
          enum: [
            "auth",
            "secrets",
            "input_validation",
            "rate_limits",
            "dangerous_exec",
            "dependency_risk",
            "environment_exposure",
            "permissions",
            "web3_base"
          ]
        },
        description: "Optional finding categories to include."
      }
    },
    required: ["filePath"],
    additionalProperties: false
  }
} as const;

export async function handleS1ScanFile(input: unknown): Promise<CallToolResult> {
  const parsedInput = S1ScanFileInputSchema.parse(input);
  const result = await scanFile(parsedInput);

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
