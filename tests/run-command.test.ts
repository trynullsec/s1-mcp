import { describe, expect, it, vi } from "vitest";

vi.mock("execa", () => ({
  execa: vi.fn().mockResolvedValue({
    stdout: "ok",
    stderr: ""
  })
}));

describe("runCommand", () => {
  it("executes commands without a shell string", async () => {
    const { execa } = await import("execa");
    const { runCommand } = await import("../src/utils/run-command.js");

    await runCommand({
      command: "npx",
      args: ["-y", "@trynullsec/s1-zk", "rules", "--no-banner"]
    });

    expect(execa).toHaveBeenCalledWith(
      "npx",
      ["-y", "@trynullsec/s1-zk", "rules", "--no-banner"],
      expect.objectContaining({ shell: false })
    );
  });
});
