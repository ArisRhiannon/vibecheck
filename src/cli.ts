#!/usr/bin/env bun
import { existsSync } from "node:fs";
import { scanProject, meetsFail } from "./engine";
import { loadConfig } from "./config";
import { formatText, toJSON } from "./report";
import { RULES } from "./catalog";

function die(msg: string, code = 1): never {
  console.error(msg);
  process.exit(code);
}

const HELP = `vibecheck — offline "safe to ship?" gate for vibe-coded apps (no AI, no network)
usage:
  vibecheck [scan] [dir] [--json] [--ci]   scan a project (default dir: .)
  vibecheck explain <RULE-ID>              describe a rule and its fix
flags:
  --json   machine-readable output (for agents / CI)
  --ci     exit non-zero if any finding >= failSeverity (default: high)`;

const argv = process.argv.slice(2);
let json = false, ci = false;
const pos: string[] = [];
for (const a of argv) {
  if (a === "--json") json = true;
  else if (a === "--ci") ci = true;
  else if (a === "-h" || a === "--help") { console.log(HELP); process.exit(0); }
  else pos.push(a);
}
const cmd = pos[0] === "scan" || pos[0] === "explain" ? (pos.shift() as string) : "scan";

if (cmd === "explain") {
  const id = pos[0];
  if (!id) die("usage: vibecheck explain <RULE-ID>", 2);
  const r = RULES[id];
  if (!r) die(`unknown rule: ${id}`, 2);
  console.log(`${id}\n  ${r.summary}\n  fix: ${r.fix}`);
  process.exit(0);
}

const dir = pos[0] ?? ".";
if (!existsSync(dir)) die(`no such directory: ${dir}`);
try {
  const cfg = loadConfig(dir);
  const res = scanProject(dir, cfg);
  console.log(json ? toJSON(res) : formatText(res));
  process.exit(ci && meetsFail(res.findings, cfg.failSeverity ?? "high") ? 1 : 0);
} catch (e) {
  die(`vibecheck: ${(e as Error).message}`);
}
