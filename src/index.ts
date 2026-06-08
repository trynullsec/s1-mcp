#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from "@modelcontextprotocol/sdk/types.js";

import { handleS1ExplainFinding, s1ExplainFindingTool } from "./tools/s1-explain-finding.js";
import { handleS1Gate, s1GateTool } from "./tools/s1-gate.js";
import { handleS1ScanFile, s1ScanFileTool } from "./tools/s1-scan-file.js";
import { handleS1ScanRepo, s1ScanRepoTool } from "./tools/s1-scan-repo.js";
import { handleS1ZkExplain, s1ZkExplainTool } from "./tools/s1-zk-explain.js";
import { handleS1ZkRules, s1ZkRulesTool } from "./tools/s1-zk-rules.js";
import { handleS1ZkScan, s1ZkScanTool } from "./tools/s1-zk-scan.js";

const server = new Server(
  {
    name: "@trynullsec/s1-mcp",
    version: "0.1.0"
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    s1ScanRepoTool,
    s1ScanFileTool,
    s1ExplainFindingTool,
    s1GateTool,
    s1ZkScanTool,
    s1ZkExplainTool,
    s1ZkRulesTool
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: input } = request.params;

  switch (name) {
    case s1ZkScanTool.name:
      return handleS1ZkScan(input);
    case s1ZkExplainTool.name:
      return handleS1ZkExplain(input);
    case s1ZkRulesTool.name:
      return handleS1ZkRules(input);
    case s1ScanRepoTool.name:
      return handleS1ScanRepo(input);
    case s1ScanFileTool.name:
      return handleS1ScanFile(input);
    case s1ExplainFindingTool.name:
      return handleS1ExplainFinding(input);
    case s1GateTool.name:
      return handleS1Gate(input);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
