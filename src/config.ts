import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Severity } from "./types";

export interface VibecheckConfig {
  ignoreRules?: string[];
  allowPaths?: string[];
  failSeverity?: Severity;
}

/** Load `.vibecheck.json` from `dir`, tolerating absence/invalid JSON. */
export function loadConfig(dir: string): VibecheckConfig {
  const p = join(dir, ".vibecheck.json");
  if (!existsSync(p)) return {};
  try {
    const j = JSON.parse(readFileSync(p, "utf8"));
    return j && typeof j === "object" ? (j as VibecheckConfig) : {};
  } catch {
    return {};
  }
}
