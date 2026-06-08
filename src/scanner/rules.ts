import path from "node:path";

import type { Finding } from "./types.js";
import {
  isEnvExample,
  isEnvFile,
  lineNumberForIndex,
  makeFinding,
  relativeFile
} from "./utils.js";

type FileContext = {
  root: string;
  filePath: string;
  content: string;
};

type MatchRule = {
  id: string;
  title: string;
  severity: Finding["severity"];
  category: Finding["category"];
  confidence: Finding["confidence"];
  productionBlocker: boolean;
  pattern: RegExp;
  explanation: string;
  exploitScenario: string;
  recommendation: string;
};

const secretRules: MatchRule[] = [
  {
    id: "S1-SEC-001",
    title: "Hardcoded live secret key",
    severity: "CRITICAL",
    category: "secrets",
    confidence: "HIGH",
    productionBlocker: true,
    pattern: /\bsk_live_[A-Za-z0-9_=-]{6,}\b/g,
    explanation: "A live secret key is embedded directly in source code.",
    exploitScenario: "An attacker with source access or an error path that exposes this value can use the live key against the upstream service.",
    recommendation: "Revoke the exposed key, move it to a secret manager or environment variable, and never return it in responses."
  },
  {
    id: "S1-SEC-002",
    title: "Hardcoded API token",
    severity: "HIGH",
    category: "secrets",
    confidence: "MEDIUM",
    productionBlocker: true,
    pattern: /\b(?:sk-ant-|sk-proj-|sk-)[A-Za-z0-9_-]{16,}\b/g,
    explanation: "An API token appears to be hardcoded in the application.",
    exploitScenario: "If the repository, logs, bundles, or responses expose this value, an attacker can spend quota or access protected data.",
    recommendation: "Rotate the token and load it from server-side secret storage only."
  },
  {
    id: "S1-SEC-003",
    title: "Bearer token embedded in code",
    severity: "HIGH",
    category: "secrets",
    confidence: "MEDIUM",
    productionBlocker: true,
    pattern: /Bearer\s+[A-Za-z0-9._~+/=-]{16,}/gi,
    explanation: "A bearer token appears in source code.",
    exploitScenario: "Anyone who obtains the code can replay the bearer token to impersonate the application or user.",
    recommendation: "Rotate the token and fetch it from a server-side secret store at runtime."
  },
  {
    id: "S1-SEC-004",
    title: "Private key material in repository",
    severity: "CRITICAL",
    category: "secrets",
    confidence: "HIGH",
    productionBlocker: true,
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|0x[a-fA-F0-9]{64}/g,
    explanation: "Private key material appears to be present in a scanned file.",
    exploitScenario: "An attacker can import the key and sign transactions, deploy contracts, or access protected infrastructure.",
    recommendation: "Treat the key as compromised, rotate it, and store deployment or service keys outside the repository."
  },
  {
    id: "S1-SEC-005",
    title: "Seed phrase-like secret",
    severity: "CRITICAL",
    category: "secrets",
    confidence: "MEDIUM",
    productionBlocker: true,
    pattern: /\b(?:seed phrase|mnemonic)\b\s*[:=]\s*["'][a-z]+(?:\s+[a-z]+){11,23}["']/gi,
    explanation: "A mnemonic or seed phrase appears to be hardcoded.",
    exploitScenario: "Anyone with this phrase can recover the wallet and move funds or authorize transactions.",
    recommendation: "Move funds immediately, retire the phrase, and never store mnemonics in source code."
  },
  {
    id: "S1-SEC-006",
    title: "Database URL exposed in code",
    severity: "HIGH",
    category: "secrets",
    confidence: "HIGH",
    productionBlocker: true,
    pattern: /\b(?:DATABASE_URL|POSTGRES_URL|MYSQL_URL|MONGODB_URI)\b\s*[:=]\s*["'][^"']+["']/gi,
    explanation: "A database connection URL appears in a scanned file.",
    exploitScenario: "An attacker can use leaked credentials to read, modify, or destroy application data.",
    recommendation: "Rotate the database credentials and load connection strings from protected server-side configuration."
  },
  {
    id: "S1-SEC-007",
    title: "Webhook secret exposed in code",
    severity: "HIGH",
    category: "secrets",
    confidence: "MEDIUM",
    productionBlocker: true,
    pattern: /\b(?:WEBHOOK_SECRET|STRIPE_WEBHOOK_SECRET|SIGNING_SECRET)\b\s*[:=]\s*["'][^"']+["']/gi,
    explanation: "A webhook signing secret appears in source code.",
    exploitScenario: "An attacker can forge webhook events that the application trusts as authentic.",
    recommendation: "Rotate the secret and verify webhook signatures using a server-side environment value."
  }
];

const dangerousExecutionRules: MatchRule[] = [
  {
    id: "S1-EXEC-001",
    title: "Shell command execution",
    severity: "HIGH",
    category: "dangerous_exec",
    confidence: "HIGH",
    productionBlocker: false,
    pattern: /\bexec\s*\(/g,
    explanation: "The code executes a shell command. Shell execution is risky unless every command and argument is fixed and trusted.",
    exploitScenario: "If attacker-controlled input reaches this call, they can execute arbitrary commands on the server.",
    recommendation: "Remove shell execution or replace it with fixed commands and argument arrays using non-shell APIs."
  },
  {
    id: "S1-EXEC-002",
    title: "Synchronous shell command execution",
    severity: "HIGH",
    category: "dangerous_exec",
    confidence: "HIGH",
    productionBlocker: false,
    pattern: /\bexecSync\s*\(/g,
    explanation: "The code executes a shell command synchronously.",
    exploitScenario: "Attacker-influenced input can become command injection, and sync execution can block the event loop.",
    recommendation: "Remove shell execution or use a fixed executable with validated argument arrays."
  },
  {
    id: "S1-EXEC-003",
    title: "Dynamic code evaluation",
    severity: "HIGH",
    category: "dangerous_exec",
    confidence: "HIGH",
    productionBlocker: true,
    pattern: /\beval\s*\(|new\s+Function\s*\(/g,
    explanation: "The application evaluates code dynamically.",
    exploitScenario: "An attacker who controls evaluated input can run arbitrary JavaScript in the application context.",
    recommendation: "Replace dynamic evaluation with explicit parsing, allow-listed operations, or a safe expression evaluator."
  },
  {
    id: "S1-EXEC-004",
    title: "spawn configured with shell execution",
    severity: "HIGH",
    category: "dangerous_exec",
    confidence: "HIGH",
    productionBlocker: false,
    pattern: /\bspawn\s*\([^)]*\{[^}]*shell\s*:\s*true/gs,
    explanation: "A child process is spawned through a shell.",
    exploitScenario: "Shell metacharacters in attacker-controlled arguments can alter the executed command.",
    recommendation: "Use shell: false and pass a fixed executable with a validated argv array."
  }
];

const solidityRules: MatchRule[] = [
  {
    id: "S1-EVM-001",
    title: "tx.origin authorization",
    severity: "HIGH",
    category: "web3_base",
    confidence: "HIGH",
    productionBlocker: true,
    pattern: /\btx\.origin\b/g,
    explanation: "The contract references tx.origin, which is unsafe for authorization.",
    exploitScenario: "A malicious contract can trick a privileged wallet into calling it, then pass tx.origin checks in the target contract.",
    recommendation: "Use msg.sender with explicit role checks instead of tx.origin."
  },
  {
    id: "S1-EVM-002",
    title: "delegatecall usage",
    severity: "HIGH",
    category: "web3_base",
    confidence: "HIGH",
    productionBlocker: true,
    pattern: /\.delegatecall\s*\(/g,
    explanation: "The contract uses delegatecall, which executes external code in the caller's storage context.",
    exploitScenario: "A malicious or upgradeable target can overwrite storage, seize ownership, or drain funds.",
    recommendation: "Avoid delegatecall unless it is part of a reviewed proxy pattern with strict implementation controls."
  },
  {
    id: "S1-EVM-003",
    title: "selfdestruct usage",
    severity: "HIGH",
    category: "web3_base",
    confidence: "HIGH",
    productionBlocker: true,
    pattern: /\bselfdestruct\s*\(/g,
    explanation: "The contract can destroy itself or force-send funds.",
    exploitScenario: "If reachable by an attacker or compromised owner, contract functionality and balances can be disrupted.",
    recommendation: "Remove selfdestruct unless it is part of a clearly documented and access-controlled migration path."
  },
  {
    id: "S1-EVM-004",
    title: "Low-level call",
    severity: "MEDIUM",
    category: "web3_base",
    confidence: "MEDIUM",
    productionBlocker: false,
    pattern: /\.call\s*(?:\{[^}]*\})?\s*\(/g,
    explanation: "The contract uses a low-level call.",
    exploitScenario: "Unchecked or poorly ordered low-level calls can create reentrancy, error handling, or fund transfer bugs.",
    recommendation: "Use typed interfaces where possible, check return values, and follow checks-effects-interactions."
  },
  {
    id: "S1-EVM-005",
    title: "Potential unrestricted mint",
    severity: "HIGH",
    category: "web3_base",
    confidence: "MEDIUM",
    productionBlocker: true,
    pattern: /function\s+mint\s*\([^)]*\)\s*(?:public|external)(?![^{;]*(?:onlyOwner|onlyRole|auth|authorized))/g,
    explanation: "A public or external mint function does not show an obvious access-control modifier.",
    exploitScenario: "Anyone may be able to mint tokens or assets on Base/EVM if the function lacks an internal guard.",
    recommendation: "Add explicit access control or supply constraints to mint functions."
  },
  {
    id: "S1-EVM-006",
    title: "Owner-controlled drain or fee control",
    severity: "MEDIUM",
    category: "permissions",
    confidence: "LOW",
    productionBlocker: false,
    pattern: /\b(?:drain|withdrawAll|setTax|setFee|blacklist)\s*\(/gi,
    explanation: "The contract includes owner-style controls that may affect funds, fees, or transfers.",
    exploitScenario: "Centralized controls can be abused by a compromised owner or hidden from users before launch.",
    recommendation: "Document privileged controls, constrain them with timelocks or multisig, and remove hidden fee or drain paths."
  }
];

export function scanFileContent(root: string, filePath: string, content: string): Finding[] {
  const context = { root, filePath, content };
  const findings: Finding[] = [];
  const extension = path.extname(filePath);

  findings.push(...runRules(context, secretRules));
  findings.push(...detectNextPublicSecrets(context));
  findings.push(...detectSecretResponses(context));
  findings.push(...detectEnvironmentExposure(context));

  if (extension !== ".json" && !isEnvExample(filePath)) {
    findings.push(...runRules(context, dangerousExecutionRules));
    findings.push(...detectUserInputCommandExecution(context));
    findings.push(...detectAuthValidationAndRateLimits(context));
  }

  if (extension === ".json") {
    findings.push(...detectPackageJsonRisks(context));
  }

  if (extension === ".sol") {
    findings.push(...runRules(context, solidityRules));
  }

  if (/\b(?:PRIVATE_KEY|DEPLOYER_KEY)\b\s*[:=]\s*["']?0x[a-fA-F0-9]{64}/.test(content)) {
    findings.push(
      makeFinding({
        id: "S1-EVM-007",
        title: "Base/EVM deploy private key in script",
        severity: "CRITICAL",
        category: "web3_base",
        file: relativeFile(root, filePath),
        line: lineNumberForIndex(content, content.search(/\b(?:PRIVATE_KEY|DEPLOYER_KEY)\b/)),
        evidence: content.match(/\b(?:PRIVATE_KEY|DEPLOYER_KEY)\b[^\n]*/)?.[0],
        explanation: "A Base/EVM deploy script appears to contain a raw private key.",
        exploitScenario: "An attacker can deploy, upgrade, or transfer assets as the deployer wallet.",
        recommendation: "Rotate the wallet, move deploy keys to protected CI or hardware-backed signing, and avoid live keys in scripts.",
        productionBlocker: true,
        confidence: "HIGH"
      })
    );
  }

  if (/\b(?:forge|hardhat)\b[^\n]*(?:--broadcast|--rpc-url|mainnet|base)/i.test(content)) {
    findings.push(
      makeFinding({
        id: "S1-EVM-008",
        title: "Live Base/EVM broadcast deploy pattern",
        severity: "HIGH",
        category: "web3_base",
        file: relativeFile(root, filePath),
        line: lineNumberForIndex(content, content.search(/\b(?:forge|hardhat)\b/i)),
        evidence: content.match(/\b(?:forge|hardhat)\b[^\n]*/i)?.[0],
        explanation: "A live deploy or broadcast command pattern appears in a scanned script.",
        exploitScenario: "Accidental execution can deploy unreviewed contracts or broadcast transactions with production funds.",
        recommendation: "Separate dry-run and live deployment scripts, require explicit approvals, and keep private keys out of scripts.",
        productionBlocker: true,
        confidence: "MEDIUM"
      })
    );
  }

  return dedupeFindings(findings);
}

function runRules(context: FileContext, rules: MatchRule[]): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    for (const match of context.content.matchAll(pattern)) {
      findings.push(
        makeFinding({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          file: relativeFile(context.root, context.filePath),
          line: match.index === undefined ? undefined : lineNumberForIndex(context.content, match.index),
          evidence: match[0],
          explanation: rule.explanation,
          exploitScenario: rule.exploitScenario,
          recommendation: rule.recommendation,
          productionBlocker: rule.productionBlocker,
          confidence: rule.confidence
        })
      );
    }
  }

  return findings;
}

function detectNextPublicSecrets(context: FileContext): Finding[] {
  const findings: Finding[] = [];
  const pattern = /\bNEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|KEY|TOKEN|DATABASE|WEBHOOK)[A-Z0-9_]*\b\s*[:=]\s*["']?[^"',\n\s]*/g;

  for (const match of context.content.matchAll(pattern)) {
    findings.push(
      makeFinding({
        id: "S1-ENV-001",
        title: "Secret assigned to NEXT_PUBLIC environment variable",
        severity: "CRITICAL",
        category: "environment_exposure",
        file: relativeFile(context.root, context.filePath),
        line: match.index === undefined ? undefined : lineNumberForIndex(context.content, match.index),
        evidence: match[0],
        explanation: "NEXT_PUBLIC variables are exposed to browser clients in Next.js applications.",
        exploitScenario: "A user can view the bundled client code and recover the exposed secret.",
        recommendation: "Move secrets to server-only environment variables without the NEXT_PUBLIC prefix.",
        productionBlocker: true,
        confidence: "HIGH"
      })
    );
  }

  return findings;
}

function detectSecretResponses(context: FileContext): Finding[] {
  if (!/\b(?:NextResponse|Response)\.json\s*\(|\bjson\s*\(/.test(context.content)) {
    return [];
  }

  const findings: Finding[] = [];
  const responseSecretPattern = /\b(?:apiKey|secret|token|password|privateKey|DATABASE_URL)\b/g;
  for (const match of context.content.matchAll(responseSecretPattern)) {
    findings.push(
      makeFinding({
        id: "S1-SEC-008",
        title: "Secret-like value returned in JSON response",
        severity: "CRITICAL",
        category: "secrets",
        file: relativeFile(context.root, context.filePath),
        line: match.index === undefined ? undefined : lineNumberForIndex(context.content, match.index),
        evidence: lineAt(context.content, match.index ?? 0),
        explanation: "A JSON response appears to include a secret-like value.",
        exploitScenario: "A client or attacker calling this endpoint can receive credentials directly from the API.",
        recommendation: "Never include secrets in API responses. Return only the minimum non-sensitive fields needed by the client.",
        productionBlocker: true,
        confidence: "MEDIUM"
      })
    );
  }

  return findings.slice(0, 3);
}

function detectEnvironmentExposure(context: FileContext): Finding[] {
  const findings: Finding[] = [];

  if (isEnvFile(context.filePath) && !isEnvExample(context.filePath)) {
    findings.push(
      makeFinding({
        id: "S1-ENV-002",
        title: ".env file scanned",
        severity: "HIGH",
        category: "environment_exposure",
        file: relativeFile(context.root, context.filePath),
        explanation: "A concrete environment file is present in the scanned tree.",
        exploitScenario: "If this file is committed or shared, production credentials may leak.",
        recommendation: "Keep only .env.example in source control and ensure concrete .env files are ignored.",
        productionBlocker: true,
        confidence: "HIGH"
      })
    );
  }

  const processEnvPattern = /\b(?:NextResponse|Response)\.json\s*\([^)]*process\.env|console\.(?:log|error|warn)\s*\([^)]*(?:process\.env|SECRET|TOKEN|KEY)/gs;
  for (const match of context.content.matchAll(processEnvPattern)) {
    findings.push(
      makeFinding({
        id: "S1-ENV-003",
        title: "Environment or secret logged/returned",
        severity: "CRITICAL",
        category: "environment_exposure",
        file: relativeFile(context.root, context.filePath),
        line: match.index === undefined ? undefined : lineNumberForIndex(context.content, match.index),
        evidence: match[0],
        explanation: "The code appears to return or log environment values or secret-like variables.",
        exploitScenario: "Secrets can leak to clients, observability systems, or shared logs.",
        recommendation: "Remove secret logging and never serialize process.env into responses.",
        productionBlocker: true,
        confidence: "HIGH"
      })
    );
  }

  return findings;
}

function detectUserInputCommandExecution(context: FileContext): Finding[] {
  const content = context.content;
  const hasRequestBody = /\b(?:body|query|params|searchParams|req)\b/.test(content);
  const commandFromBody = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:body|query|params|searchParams|req)\b[^;\n]*/g;
  const taintedNames = new Set<string>();

  for (const match of content.matchAll(commandFromBody)) {
    if (match[1] !== undefined && /command|cmd|script|path|url|arg/i.test(match[1])) {
      taintedNames.add(match[1]);
    }
  }

  for (const name of taintedNames) {
    const execPattern = new RegExp(`\\b(?:exec|execSync|spawn)\\s*\\(\\s*${escapeRegExp(name)}\\b`, "g");
    const match = execPattern.exec(content);
    if (match !== null) {
      return [
        makeFinding({
          id: "S1-EXEC-005",
          title: "User input reaches command execution",
          severity: "CRITICAL",
          category: "dangerous_exec",
          file: relativeFile(context.root, context.filePath),
          line: lineNumberForIndex(content, match.index),
          evidence: lineAt(content, match.index),
          explanation: "Request-controlled input appears to flow into command execution.",
          exploitScenario: "A caller can submit shell metacharacters or a full command and execute arbitrary code on the server.",
          recommendation: "Remove this behavior. If command execution is unavoidable, use a fixed executable with validated arguments and shell disabled.",
          productionBlocker: true,
          confidence: "HIGH",
          patchSuggestion: nextAdminPatchSuggestion()
        })
      ];
    }
  }

  if (hasRequestBody && /\b(?:exec|execSync|spawn)\s*\(\s*(?:body|query|params|searchParams|req)\b/.test(content)) {
    const index = content.search(/\b(?:exec|execSync|spawn)\s*\(/);
    return [
      makeFinding({
        id: "S1-EXEC-005",
        title: "User input reaches command execution",
        severity: "CRITICAL",
        category: "dangerous_exec",
        file: relativeFile(context.root, context.filePath),
        line: lineNumberForIndex(content, index),
        evidence: lineAt(content, index),
        explanation: "Request-controlled input appears to flow into command execution.",
        exploitScenario: "A caller can execute arbitrary server-side commands.",
        recommendation: "Remove request-controlled command execution and replace it with explicit server-side actions.",
        productionBlocker: true,
        confidence: "HIGH",
        patchSuggestion: nextAdminPatchSuggestion()
      })
    ];
  }

  return [];
}

function detectAuthValidationAndRateLimits(context: FileContext): Finding[] {
  const content = context.content;
  const normalizedPath = context.filePath.split(path.sep).join("/");
  const isApiRoute = /\/api\//.test(normalizedPath) || /\bexport\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE|GET)\b/.test(content);
  const isMutation = /\bexport\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)\b/.test(content);
  const isAdmin = /\/api\/admin(?:\/|$)/.test(normalizedPath) || /\badmin\s*:\s*true\b/.test(content);

  if (!isApiRoute) {
    return [];
  }

  const findings: Finding[] = [];
  const hasAuth = /\b(?:auth|session|getServerSession|currentUser|requireAuth|isAdmin|role|permission|authorize)\b/i.test(content);
  const hasValidation = /\b(?:z\.object|safeParse|parse\(|schema|validator|yup|joi|valibot)\b/.test(content);
  const hasRateLimit = /\b(?:rateLimit|ratelimit|limiter|Upstash|too many requests|429)\b/i.test(content);

  if (isAdmin && !hasAuth) {
    const index = content.search(/\bexport\s+async\s+function\b|\badmin\s*:\s*true\b/);
    findings.push(
      makeFinding({
        id: "S1-AUTH-001",
        title: "Admin API route without visible authorization",
        severity: "HIGH",
        category: "auth",
        file: relativeFile(context.root, context.filePath),
        line: index >= 0 ? lineNumberForIndex(content, index) : undefined,
        evidence: index >= 0 ? lineAt(content, index) : undefined,
        explanation: "An admin API handler does not show an obvious session, role, or permission check.",
        exploitScenario: "An unauthenticated caller can reach admin-only behavior or observe admin-only response fields.",
        recommendation: "Require authentication and an explicit admin role or permission check before executing handler logic.",
        productionBlocker: true,
        confidence: "HIGH",
        patchSuggestion: nextAdminPatchSuggestion()
      })
    );
  } else if (isMutation && !hasAuth) {
    const index = content.search(/\bexport\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)\b/);
    findings.push(
      makeFinding({
        id: "S1-AUTH-002",
        title: "Mutation endpoint without visible authentication",
        severity: "MEDIUM",
        category: "auth",
        file: relativeFile(context.root, context.filePath),
        line: index >= 0 ? lineNumberForIndex(content, index) : undefined,
        evidence: index >= 0 ? lineAt(content, index) : undefined,
        explanation: "A mutation endpoint does not show an obvious authentication check.",
        exploitScenario: "Attackers may be able to create, update, or delete data without an authenticated session.",
        recommendation: "Add an authentication check and authorize the specific mutation."
      ,
        productionBlocker: false,
        confidence: "MEDIUM"
      })
    );
  }

  if (/\bawait\s+req\.json\s*\(\s*\)/.test(content) && !hasValidation) {
    const index = content.search(/\bawait\s+req\.json\s*\(\s*\)/);
    findings.push(
      makeFinding({
        id: "S1-VAL-001",
        title: "Request JSON parsed without schema validation",
        severity: "MEDIUM",
        category: "input_validation",
        file: relativeFile(context.root, context.filePath),
        line: lineNumberForIndex(content, index),
        evidence: lineAt(content, index),
        explanation: "The handler parses JSON from the request without an obvious schema validation step.",
        exploitScenario: "Unexpected shapes or malicious values can reach sensitive logic, causing authorization bypasses, injections, or crashes.",
        recommendation: "Validate request bodies with Zod or an equivalent schema before using values.",
        productionBlocker: false,
        confidence: "HIGH",
        patchSuggestion: nextAdminPatchSuggestion()
      })
    );
  }

  if (isMutation && !hasRateLimit) {
    const index = content.search(/\bexport\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)\b/);
    findings.push(
      makeFinding({
        id: "S1-RATE-001",
        title: "Mutation API route without visible rate limit",
        severity: "MEDIUM",
        category: "rate_limits",
        file: relativeFile(context.root, context.filePath),
        line: index >= 0 ? lineNumberForIndex(content, index) : undefined,
        evidence: index >= 0 ? lineAt(content, index) : undefined,
        explanation: "A state-changing API route does not show an obvious rate limit.",
        exploitScenario: "Attackers can brute force, spam expensive operations, or amplify abuse through this endpoint.",
        recommendation: "Add route-level rate limiting with a production-backed limiter and return 429 on abuse.",
        productionBlocker: false,
        confidence: "MEDIUM",
        patchSuggestion: nextAdminPatchSuggestion()
      })
    );
  }

  return findings;
}

function detectPackageJsonRisks(context: FileContext): Finding[] {
  if (path.basename(context.filePath) !== "package.json") {
    return [];
  }

  const findings: Finding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(context.content);
  } catch {
    return [];
  }

  if (!isRecord(parsed)) {
    return [];
  }

  const scripts = isRecord(parsed.scripts) ? parsed.scripts : {};
  for (const scriptName of ["preinstall", "install", "postinstall"]) {
    const value = scripts[scriptName];
    if (typeof value === "string") {
      findings.push(
        makeFinding({
          id: "S1-DEP-001",
          title: "Install lifecycle script in package.json",
          severity: "MEDIUM",
          category: "dependency_risk",
          file: relativeFile(context.root, context.filePath),
          evidence: `"${scriptName}": "${value}"`,
          explanation: "Package install lifecycle scripts run automatically during dependency installation.",
          exploitScenario: "A compromised or unexpected script can execute code in developer, CI, or production build environments.",
          recommendation: "Remove install lifecycle scripts unless required, document why they are needed, and review them before release.",
          productionBlocker: false,
          confidence: "HIGH"
        })
      );
    }
  }

  for (const [scriptName, value] of Object.entries(scripts)) {
    if (typeof value === "string" && /\b(?:curl|wget)\b.+\|\s*(?:sh|bash)|rm\s+-rf\s+\/|chmod\s+\+x/i.test(value)) {
      findings.push(
        makeFinding({
          id: "S1-DEP-002",
          title: "Suspicious package script",
          severity: "HIGH",
          category: "dependency_risk",
          file: relativeFile(context.root, context.filePath),
          evidence: `"${scriptName}": "${value}"`,
          explanation: "A package script contains behavior commonly associated with unsafe shell execution.",
          exploitScenario: "A developer or CI job can run a script that downloads and executes unreviewed code or performs destructive actions.",
          recommendation: "Replace shell-piped downloads and destructive commands with reviewed, pinned tooling.",
          productionBlocker: true,
          confidence: "MEDIUM"
        })
      );
    }
  }

  const dependencySections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
  for (const section of dependencySections) {
    const dependencies = parsed[section];
    if (!isRecord(dependencies)) {
      continue;
    }

    for (const [name, value] of Object.entries(dependencies)) {
      if (typeof value === "string" && /^(?:git\+|git:|https?:\/\/)/i.test(value)) {
        findings.push(
          makeFinding({
            id: "S1-DEP-003",
            title: "Dependency installed from git or HTTP URL",
            severity: "MEDIUM",
            category: "dependency_risk",
            file: relativeFile(context.root, context.filePath),
            evidence: `"${name}": "${value}"`,
            explanation: "A dependency is sourced from a git or HTTP URL instead of a package registry version.",
            exploitScenario: "The dependency source may change or bypass registry integrity guarantees, creating supply-chain risk.",
            recommendation: "Pin dependencies to registry versions or immutable commit hashes with reviewed provenance.",
            productionBlocker: false,
            confidence: "HIGH"
          })
        );
      }
    }
  }

  return findings;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const deduped: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.id}:${finding.file}:${finding.line ?? "none"}:${finding.evidence ?? ""}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(finding);
    }
  }

  return deduped;
}

function lineAt(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index) + 1;
  const end = content.indexOf("\n", index);
  return content.slice(start, end === -1 ? content.length : end).trim();
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nextAdminPatchSuggestion() {
  return {
    summary: "Harden the API route before shipping.",
    steps: [
      "Remove hardcoded secrets and rotate any exposed live keys.",
      "Delete request-controlled exec/body.command behavior.",
      "Add an authentication and admin authorization check before handler logic.",
      "Validate req.json() with a Zod schema before using input.",
      "Do not return secret values in JSON responses.",
      "Add a route-level rate limit before expensive or sensitive work."
    ]
  };
}
