import { execa, type Options } from "execa";

export type CommandSpec = {
  command: string;
  args: string[];
};

export type CommandResult = {
  stdout: string;
  stderr: string;
};

export async function runCommand(
  spec: CommandSpec,
  options: Options = {}
): Promise<CommandResult> {
  const result = await execa(spec.command, spec.args, {
    shell: false,
    encoding: "utf8",
    reject: true,
    ...options
  });

  return {
    stdout: String(result.stdout ?? ""),
    stderr: String(result.stderr ?? "")
  };
}
