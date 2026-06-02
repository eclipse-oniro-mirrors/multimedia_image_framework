#!/usr/bin/env node
import { installKnowledgeBuilder, PACKAGE_NAME } from "../src/install.mjs";

function printHelp() {
  process.stdout.write(`OpenCode image knowledge installer

Usage:
  npx ${PACKAGE_NAME} install [--dry-run] [--force] [--config-dir <path>]

Commands:
  install      Install the global OpenCode plugin config, command, and agent.

Options:
  --dry-run    Show planned changes without writing files.
  --force      Overwrite existing managed command or agent templates.
  --config-dir Override the OpenCode config directory.
  -h, --help   Show this help.
`);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = { command };
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--force") {
      options.force = true;
    } else if (arg === "--config-dir") {
      i += 1;
      if (!rest[i]) {
        throw new Error("--config-dir requires a path.");
      }
      options.configDir = rest[i];
    } else if (arg === "-h" || arg === "--help") {
      options.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.command || options.help) {
    printHelp();
    return;
  }
  if (options.command !== "install") {
    throw new Error(`Unknown command: ${options.command}`);
  }

  const result = await installKnowledgeBuilder(options);
  if (options.dryRun) {
    process.stdout.write(`[dry-run] OpenCode config dir: ${result.configDir}\n`);
  } else {
    process.stdout.write(`OpenCode config dir: ${result.configDir}\n`);
  }
  if (result.changed.length === 0) {
    process.stdout.write("No changes needed.\n");
  } else {
    process.stdout.write(`Changed:\n${result.changed.map((item) => `- ${item}`).join("\n")}\n`);
  }
  process.stdout.write(`Run in an OpenCode session: ${result.command}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
