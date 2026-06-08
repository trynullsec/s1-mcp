import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { evaluateGate } from "../scanner/utils.js";
import { scanRepo } from "../scanner/scan.js";
import { S1GateInputSchema } from "../types.js";

export const s1GateTool = {
  name: "s1_gate",
  description:
    "Evaluate production readiness from findings or by scanning a target path first. Blocks critical/high issues by default.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Optional target path to scan before gate evaluation."
      },
      findings: {
        type: "array",
        items: { type: "object" },
        description: "Optional findings returned by s1_scan_repo or s1_scan_file."
      },
      policy: {
        type: "object",
        properties: {
          blockCritical: {
            type: "boolean",
            description: "Block on CRITICAL findings. Defaults to true."
          },
          blockHigh: {
            type: "boolean",
            description: "Block on HIGH findings. Defaults to true."
          },
          requireDimensions: {
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
            description: "Optional finding dimensions expected in the scan result."
          }
        },
        additionalProperties: false
      }
    },
    additionalProperties: false
  }
} as const;

export async function handleS1Gate(input: unknown): Promise<CallToolResult> {
  const parsedInput = S1GateInputSchema.parse(input);
  const findings =
    parsedInput.target !== undefined
      ? (await scanRepo({ target: parsedInput.target })).issues
      : (parsedInput.findings ?? []);
  const result = evaluateGate(findings, {
    blockCritical: parsedInput.policy.blockCritical,
    blockHigh: parsedInput.policy.blockHigh,
    requireDimensions: parsedInput.policy.requireDimensions
  });

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
