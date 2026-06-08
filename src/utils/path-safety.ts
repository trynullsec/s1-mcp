import path from "node:path";

const NULL_BYTE = "\0";

export function validateTargetPath(target: string, cwd = process.cwd()): string {
  if (target.includes(NULL_BYTE)) {
    throw new Error("Target path must not contain null bytes.");
  }

  const trimmedTarget = target.trim();

  if (trimmedTarget.length === 0) {
    throw new Error("Target path is required.");
  }

  if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmedTarget)) {
    throw new Error("Target path must be a local file system path.");
  }

  const resolvedCwd = path.resolve(cwd);
  const resolvedTarget = path.resolve(resolvedCwd, trimmedTarget);
  const relativeTarget = path.relative(resolvedCwd, resolvedTarget);

  if (
    relativeTarget === ".." ||
    relativeTarget.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativeTarget)
  ) {
    throw new Error("Target path must stay within the current working directory.");
  }

  return resolvedTarget;
}
