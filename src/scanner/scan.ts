import fs from "node:fs/promises";
import path from "node:path";

import type { FindingCategory, ScanResult } from "./types.js";
import { scanFileContent } from "./rules.js";
import {
  discoverSupportedFiles,
  filterByCategory,
  isSupportedFile,
  makeScanResult
} from "./utils.js";
import { validateTargetPath } from "../utils/path-safety.js";

export type ScanRepoInput = {
  target: string;
  ruleCategories?: FindingCategory[];
};

export type ScanFileInput = {
  filePath: string;
  ruleCategories?: FindingCategory[];
};

export async function scanRepo(input: ScanRepoInput): Promise<ScanResult> {
  const target = validateTargetPath(input.target);
  const files = await discoverSupportedFiles(target);

  if (files.length === 0) {
    return makeScanResult(
      target,
      0,
      [],
      "No supported application files were found. This is not a secure/pass result."
    );
  }

  const issues = [];
  for (const filePath of files) {
    const content = await fs.readFile(filePath, "utf8");
    issues.push(...scanFileContent(target, filePath, content));
  }

  return makeScanResult(target, files.length, filterByCategory(issues, input.ruleCategories));
}

export async function scanFile(input: ScanFileInput): Promise<ScanResult> {
  const filePath = validateTargetPath(input.filePath);

  if (!isSupportedFile(filePath)) {
    return makeScanResult(
      filePath,
      0,
      [],
      `Unsupported file extension for ${path.basename(filePath)}. Supported files: .ts, .tsx, .js, .jsx, .mjs, .cjs, .json, .env.example, .sol.`
    );
  }

  const content = await fs.readFile(filePath, "utf8");
  const root = path.dirname(filePath);
  const issues = scanFileContent(root, filePath, content);
  return makeScanResult(filePath, 1, filterByCategory(issues, input.ruleCategories));
}
