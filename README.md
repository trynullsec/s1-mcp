# Nullsec S1 MCP

[![npm](https://img.shields.io/npm/v/s1-mcp.svg)](https://www.npmjs.com/package/s1-mcp)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io/)
[![MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Security scanning tools for MCP-compatible coding agents.

`s1-mcp` brings Nullsec S1-style security checks into Cursor, Claude Desktop, and other MCP clients. General app/repo scanning is deterministic and local-first: it does not call a hosted S1 API, does not require an LLM, and does not claim a project is secure just because no supported files were found.

The server also keeps the existing `s1_zk_*` tools for Circom and Halo2 circuits through `@trynullsec/s1-zk`.

## Install

Use it directly with `npx`:

```sh
npx -y s1-mcp
```

Or install it in a project:

```sh
npm install --save-dev s1-mcp
npx s1-mcp
```

Requires Node.js 20 or newer.

## MCP Config

Add this server to Cursor or Claude Desktop:

```json
{
  "mcpServers": {
    "nullsec-s1": {
      "command": "npx",
      "args": ["-y", "s1-mcp"]
    }
  }
}
```

Once connected, ask your agent to run `s1_scan_repo`, `s1_scan_file`, `s1_gate`, `s1_explain_finding`, or the ZK-specific `s1_zk_*` tools.

## General App Tools

### `s1_scan_repo`

Recursively scans supported app files under a target path.

Supported files:

- `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`
- `.json`
- `.env.example` for key-name exposure checks
- `.sol` for Base/EVM Solidity checks

Ignored by default: `node_modules`, `.git`, `.next`, `dist`, `build`, `coverage`, generated lockfile internals, `pnpm-lock.yaml`, and `yarn.lock`.

Input:

```json
{
  "target": "app",
  "ruleCategories": ["auth", "secrets", "dangerous_exec"]
}
```

Output includes:

- `target`
- `filesScanned`
- `rulesExecuted`
- severity `summary`
- `issues`
- `productionGate`
- `unsupported` when no supported files are found

### `s1_scan_file`

Scans one supported file with the same deterministic rules. Unsupported extensions return an explicit unsupported result instead of a pass/secure verdict.

```json
{
  "filePath": "app/api/admin/route.ts"
}
```

### `s1_gate`

Evaluates production readiness from existing findings or scans a target first.

```json
{
  "target": "app",
  "policy": {
    "blockCritical": true,
    "blockHigh": true,
    "requireDimensions": ["auth", "secrets", "rate_limits"]
  }
}
```

Blocks by default on critical findings, high findings, secret exposure, dangerous execution with user input, live Base/EVM deploy key patterns, and unauthenticated admin routes with dangerous behavior.

### `s1_explain_finding`

Explains a finding for a developer, founder, or auditor using local templates.

```json
{
  "findingId": "S1-EXEC-005",
  "audience": "developer"
}
```

You can also pass a full finding object returned by `s1_scan_repo` or `s1_scan_file`.

## Deterministic Rule Coverage

General scanning catches common AI-generated app risks:

- Secrets: hardcoded OpenAI/Anthropic/Stripe-style keys, `sk_live_`, bearer tokens, private keys, seed phrases, database URLs, webhook secrets, secrets returned in JSON, and secret-like `NEXT_PUBLIC_` variables.
- Dangerous execution: `child_process.exec`, `execSync`, `spawn` with `shell: true`, user input flowing into command execution, `eval`, and `new Function`.
- Auth: admin API routes without visible session/role checks, admin responses without auth, and mutation endpoints without visible auth.
- Input validation: `await req.json()` without visible schema validation.
- Rate limits: mutation API routes without visible rate limiting.
- Environment exposure: returning `process.env`, logging secrets, and concrete `.env` files if scanned.
- Dependency risk: install lifecycle scripts, git/http dependencies, and suspicious package scripts.
- Base/EVM Solidity: `tx.origin`, `delegatecall`, `selfdestruct`, unrestricted mint patterns, low-level calls, deploy private keys, live broadcast/deploy command patterns, and detectable hidden fee/drain controls.

No Solana assumptions are made by default; web3 wording and rules use Base/EVM terminology.

## ZK Tools

### `s1_zk_scan`

Scan Circom or Halo2-style ZK circuits using Nullsec S1-ZK.

```json
{
  "target": "circuits",
  "deep": true,
  "format": "json"
}
```

Behavior:

```sh
npx @trynullsec/s1-zk scan <target> --format json --no-banner
```

When `deep` is true, the server adds `--deep`.

### `s1_zk_explain`

Explain a Nullsec S1-ZK rule.

```json
{
  "ruleId": "NS-H2-005"
}
```

### `s1_zk_rules`

List supported Nullsec S1-ZK rules.

```json
{}
```

## Examples

Next.js API route scan:

```text
Use s1_scan_file on app/api/admin/route.ts and explain any production blockers.
```

Base/EVM contract scan:

```text
Use s1_scan_repo on contracts/ and then run s1_gate with blockHigh enabled.
```

ZK circuit scan:

```text
Use s1_zk_scan on circuits/ with deep mode enabled.
```

## Security Notes

- General scanning is deterministic and local-only.
- Target paths must stay within the server working directory.
- General scanning performs no shell execution.
- ZK tools invoke `@trynullsec/s1-zk` through argv arrays with `shell: false`.
- The server does not send code to remote APIs.
- Evidence is sanitized to avoid returning full secrets in MCP responses.

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
