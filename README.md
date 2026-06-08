# Nullsec S1 MCP

[![npm version](https://img.shields.io/badge/npm-0.1.0-placeholder.svg)](https://www.npmjs.com/package/@trynullsec/s1-mcp)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io/)
[![MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Security tools for AI coding agents.

`@trynullsec/s1-mcp` is an MCP server that exposes Nullsec security tooling to Claude Desktop, Cursor, and other MCP-compatible AI agents. The first release wraps `@trynullsec/s1-zk` so agents can scan Circom or Halo2-style ZK circuits through structured MCP tools.

## Install

Use it directly with `npx`:

```sh
npx -y @trynullsec/s1-mcp
```

Or install it in a project:

```sh
npm install --save-dev @trynullsec/s1-mcp
npx s1-mcp
```

Requires Node.js 20 or newer.

## Claude Desktop Config

Add this server to your Claude Desktop MCP config:

```json
{
  "mcpServers": {
    "nullsec-s1": {
      "command": "npx",
      "args": ["-y", "@trynullsec/s1-mcp"]
    }
  }
}
```

## Cursor Usage

Add the same MCP server command in Cursor's MCP configuration:

```json
{
  "mcpServers": {
    "nullsec-s1": {
      "command": "npx",
      "args": ["-y", "@trynullsec/s1-mcp"]
    }
  }
}
```

Once connected, ask your AI agent to run `s1_zk_scan`, `s1_zk_explain`, or `s1_zk_rules`.

## Available Tools

### `s1_zk_scan`

Scan Circom or Halo2-style ZK circuits using Nullsec S1-ZK.

Input:

```json
{
  "target": "path/to/circuits",
  "deep": true,
  "format": "json"
}
```

Behavior:

```sh
npx @trynullsec/s1-zk scan <target> --format json --no-banner
```

When `deep` is true, the server adds `--deep`. The MCP tool returns parsed JSON.

### `s1_zk_explain`

Explain a Nullsec S1-ZK rule.

Input:

```json
{
  "ruleId": "NS-H2-005"
}
```

Behavior:

```sh
npx @trynullsec/s1-zk explain NS-H2-005 --no-banner
```

The MCP tool returns text.

### `s1_zk_rules`

List supported Nullsec S1-ZK rules.

Input:

```json
{}
```

Behavior:

```sh
npx @trynullsec/s1-zk rules --no-banner
```

The MCP tool returns text.

### `s1_scan_repo`

Placeholder for a future general Nullsec S1 repo scan.

Input:

```json
{
  "target": "path/to/repo"
}
```

Return:

```text
Not implemented yet. Use s1_zk_scan for Circom/Halo2 circuits.
```

## Security Notes

- Target paths are validated and must stay within the current working directory.
- Scanner commands are executed with argument arrays, not shell command strings.
- Shell execution is disabled to reduce shell injection risk.
- The MCP server does not expose environment secrets.
- The MCP server does not send code to remote APIs.
- S1-ZK is local deterministic analysis run through `@trynullsec/s1-zk`.

## Examples

Ask your MCP-compatible agent:

```text
Use s1_zk_scan on circuits/ with deep mode enabled.
```

Or call a rule explanation:

```json
{
  "ruleId": "NS-H2-005"
}
```

## Development

```sh
npm install
npm run build
npm test
```

Run the MCP server locally:

```sh
npm run dev
```

This package is not published yet.
