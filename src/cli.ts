#!/usr/bin/env node
/**
 * pcapport CLI.
 *
 *   pcapport <tool-name> '<json-arguments>'
 *   pcapport mcp
 *   pcapport --version
 *
 * Exit codes: 0 success, 1 error, 2 usage error.
 */
import { readFile } from "node:fs/promises";
import { callPcapportTool, TOOL_NAMES, VERSION } from "./pcapport.js";

function usage(): never {
  console.error(`Usage:
  pcapport <tool-name> '<json-arguments>'
  pcapport mcp
  pcapport --version
Tools: ${TOOL_NAMES.join(", ")}`);
  process.exit(2);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd || !(TOOL_NAMES as readonly string[]).includes(cmd)) usage();
  let args: Record<string, unknown> = {};
  const raw = rest.join(" ").trim();
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) usage();
      args = parsed as Record<string, unknown>;
    } catch {
      usage();
    }
  }
  try {
    const result = await callPcapportTool({ readFile: (p) => readFile(p) }, cmd, args);
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

void main();
