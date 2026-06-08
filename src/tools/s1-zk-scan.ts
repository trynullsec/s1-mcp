import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { S1ZkScanInputSchema, type S1ZkScanInput } from "../types.js";
import type { CommandSpec } from "../utils/run-command.js";
import { runCommand } from "../utils/run-command.js";
import { validateTargetPath } from "../utils/path-safety.js";

export const s1ZkScanTool = {
  name: "s1_zk_scan",
  description: "Scan Circom or Halo2-style ZK circuits using Nullsec S1-ZK.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Path to the Circom or Halo2 circuit directory or file."
      },
      deep: {
        type: "boolean",
        description: "Enable deeper S1-ZK analysis."
      },
      format: {
        type: "string",
        enum: ["json"],
        description: "Output format. Only json is supported by this MCP tool."
      }
    },
    required: ["target"],
    additionalProperties: false
  }
} as const;

export function buildS1ZkScanCommand(input: S1ZkScanInput): CommandSpec {
  const target = validateTargetPath(input.target);
  const args = [
    "-y",
    "@trynullsec/s1-zk",
    "scan",
    target,
    "--format",
    "json",
    "--no-banner"
  ];

  if (input.deep) {
    args.push("--deep");
  }

  return {
    command: "npx",
    args
  };
}

export async function handleS1ZkScan(input: unknown): Promise<CallToolResult> {
  const parsedInput = S1ZkScanInputSchema.parse(input);
  const result = await runCommand(buildS1ZkScanCommand(parsedInput));

  try {
    const parsedJson: unknown = JSON.parse(result.stdout);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(parsedJson, null, 2)
        }
      ]
    };
  } catch (error) {
    throw new Error(
      `S1-ZK scan returned invalid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}
