import path from "node:path";
import { describe, expect, it } from "vitest";

import { validateTargetPath } from "../src/utils/path-safety.js";

describe("validateTargetPath", () => {
  const cwd = "/workspace/project";

  it("returns an absolute path for a relative target inside cwd", () => {
    expect(validateTargetPath("circuits", cwd)).toBe(
      path.join(cwd, "circuits")
    );
  });

  it("allows an absolute target inside cwd", () => {
    expect(validateTargetPath("/workspace/project/circuits", cwd)).toBe(
      "/workspace/project/circuits"
    );
  });

  it("rejects path traversal outside cwd", () => {
    expect(() => validateTargetPath("../secrets", cwd)).toThrow(
      "current working directory"
    );
  });

  it("rejects URL-like targets", () => {
    expect(() => validateTargetPath("https://example.com/circuit", cwd)).toThrow(
      "local file system path"
    );
  });

  it("rejects null bytes", () => {
    expect(() => validateTargetPath("circuits\0evil", cwd)).toThrow(
      "null bytes"
    );
  });

  it("rejects sibling repository scans outside cwd", () => {
    expect(() => validateTargetPath("/workspace/other-app", cwd)).toThrow(
      "current working directory"
    );
  });
});
