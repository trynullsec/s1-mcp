import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { S1ZkExplainInputSchema, type S1ZkExplainInput } from "../types.js";
import type { CommandSpec } from "../utils/run-command.js";
import { runCommand } from "../utils/run-command.js";

export const s1ZkExplainTool = {
  name: "s1_zk_explain",
  description: "Explain a Nullsec S1-ZK rule.",
  inputSchema: {
    type: "object",
    properties: {
      ruleId: {
        type: "string",
        description: "Nullsec S1-ZK rule ID, for example NS-H2-005."
      }
    },
    required: ["ruleId"],
    additionalProperties: false
  }
} as const;

export function buildS1ZkExplainCommand(input: S1ZkExplainInput): CommandSpec {
  return {
    command: "npx",
    args: ["-y", "@trynullsec/s1-zk", "explain", input.ruleId, "--no-banner"]
  };
}

export async function handleS1ZkExplain(input: unknown): Promise<CallToolResult> {
  const parsedInput = S1ZkExplainInputSchema.parse(input);
  const result = await runCommand(buildS1ZkExplainCommand(parsedInput));

  return {
    content: [
      {
        type: "text",
        text: result.stdout
      }
    ]
  };
}
