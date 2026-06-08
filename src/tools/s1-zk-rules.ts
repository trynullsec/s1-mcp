import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { S1ZkRulesInputSchema } from "../types.js";
import type { CommandSpec } from "../utils/run-command.js";
import { runCommand } from "../utils/run-command.js";

export const s1ZkRulesTool = {
  name: "s1_zk_rules",
  description: "List supported Nullsec S1-ZK rules.",
  inputSchema: {
    type: "object",
    properties: {},
    additionalProperties: false
  }
} as const;

export function buildS1ZkRulesCommand(): CommandSpec {
  return {
    command: "npx",
    args: ["-y", "@trynullsec/s1-zk", "rules", "--no-banner"]
  };
}

export async function handleS1ZkRules(input: unknown): Promise<CallToolResult> {
  S1ZkRulesInputSchema.parse(input);
  const result = await runCommand(buildS1ZkRulesCommand());

  return {
    content: [
      {
        type: "text",
        text: result.stdout
      }
    ]
  };
}
