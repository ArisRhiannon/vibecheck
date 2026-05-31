import { parse } from "@babel/parser";
import _traverse, { type NodePath } from "@babel/traverse";
import * as t from "@babel/types";

// @babel/traverse is published as CJS; normalize the default export across Bun/Node/bundlers.
export const traverse = ((_traverse as unknown as { default?: typeof _traverse }).default ?? _traverse) as typeof _traverse;
export { t };
export type { NodePath };

/** Parse a source file into a Babel AST, choosing plugins by extension. Returns null on hard failure. */
function parseUncached(content: string, filename: string): t.File | null {
  const isTs = /\.(?:ts|tsx|mts|cts)$/.test(filename);
  const isJsx = /\.(?:tsx|jsx|js|mjs|cjs)$/.test(filename);
  const plugins: NonNullable<Parameters<typeof parse>[1]>["plugins"] = ["decorators-legacy"];
  if (isTs) plugins.push("typescript");
  if (isJsx) plugins.push("jsx");
  try {
    return parse(content, { sourceType: "unambiguous", errorRecovery: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, plugins });
  } catch {
    return null;
  }
}

// Memoize so a file scanned by multiple analyzers (astFindings + interprocFindings) is parsed once.
const cache = new Map<string, t.File | null>();
export function parseFile(content: string, filename: string): t.File | null {
  const key = `${filename}\u0000${content}`;
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  const ast = parseUncached(content, filename);
  if (cache.size >= 256) cache.delete(cache.keys().next().value as string);
  cache.set(key, ast);
  return ast;
}
