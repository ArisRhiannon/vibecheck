import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { type SourceFile, VibecheckError } from "./types";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", "out", ".turbo", ".cache", ".vercel"]);
const TEXT_EXT = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".json", ".yml", ".yaml",
  ".toml", ".ini", ".cfg", ".conf", ".env", ".txt", ".md", ".html", ".sql", ".sh", ".npmrc",
]);
const NAMED = new Set(["Dockerfile", ".npmrc", "Procfile", ".env"]);
const MAX_BYTES = 1_500_000;

function isTextCandidate(name: string): boolean {
  if (name.startsWith(".env")) return true;
  if (NAMED.has(name)) return true;
  const dot = name.lastIndexOf(".");
  return dot >= 0 && TEXT_EXT.has(name.slice(dot));
}

function globToRe(pattern: string): RegExp {
  let p = pattern;
  const anchored = p.startsWith("/");
  if (anchored) p = p.slice(1);
  const dirOnly = p.endsWith("/");
  if (dirOnly) p = p.slice(0, -1);
  const re = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  return new RegExp(`${anchored ? "^" : "(^|/)"}${re}${dirOnly ? "(/|$)" : "($|/)"}`);
}

function loadGitignore(root: string): (rel: string) => boolean {
  const p = join(root, ".gitignore");
  if (!existsSync(p)) return () => false;
  const res = readFileSync(p, "utf8")
    .split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("!"))
    .map(globToRe);
  return (rel) => res.some((r) => r.test(rel));
}

/** Recursively collect text files, skipping build dirs, gitignored paths, binaries, and huge files. */
export function collectFiles(root: string): SourceFile[] {
  if (!existsSync(root)) throw new VibecheckError(`no such directory: ${root}`);
  const ignored = loadGitignore(root);
  const out: SourceFile[] = [];
  const stack: string[] = [root];
  while (stack.length) {
    const dir = stack.pop() as string;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      const rel = relative(root, full).split(sep).join("/");
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || ignored(`${rel}/`) || ignored(rel)) continue;
        stack.push(full);
      } else if (e.isFile()) {
        if (!isTextCandidate(e.name) || ignored(rel)) continue;
        let st;
        try {
          st = statSync(full);
        } catch {
          continue;
        }
        if (st.size > MAX_BYTES) continue;
        let buf;
        try {
          buf = readFileSync(full);
        } catch {
          continue;
        }
        if (buf.includes(0)) continue; // binary
        out.push({ path: full, rel, content: buf.toString("utf8") });
      }
    }
  }
  out.sort((a, b) => a.rel.localeCompare(b.rel));
  return out;
}

/** 1-based line/column for a byte index within content. */
export function locate(content: string, index: number): { line: number; col: number } {
  let line = 1, col = 1;
  const n = Math.min(index, content.length);
  for (let i = 0; i < n; i++) {
    if (content[i] === "\n") {
      line++;
      col = 1;
    } else {
      col++;
    }
  }
  return { line, col };
}

/** The text of the line containing `index`, trimmed. */
export function lineAt(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  let end = content.indexOf("\n", index);
  if (end < 0) end = content.length;
  return content.slice(start, end).trim();
}
