import { traverse, t, parseFile, type NodePath } from "./ast";
import { type SourceFile } from "./types";

/** Dotted path for an identifier/member chain, or null. Computed members render as `[]`. */
export function memberPath(node: t.Node): string | null {
  if (t.isIdentifier(node)) return node.name;
  if (t.isThisExpression(node)) return "this";
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const obj = memberPath(node.object);
    if (obj === null) return null;
    if (node.computed) return `${obj}[]`;
    return t.isIdentifier(node.property) ? `${obj}.${node.property.name}` : null;
  }
  return null;
}

const REQ = /^(?:req|request|ctx|event)\.(?:body|query|params|headers|cookies|rawBody|files?)\b/;
const REQ_CALL = /^(?:req|request|ctx|event)\.(?:json|text|formData)$/;

/** Does this expression read attacker-controlled input? */
export function isSourceExpr(node: t.Node | null | undefined): boolean {
  if (!node) return false;
  if (t.isTSAsExpression(node) || t.isTSNonNullExpression(node) || t.isTSSatisfiesExpression(node) || t.isTSTypeAssertion(node)) {
    return isSourceExpr(node.expression);
  }
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const p = memberPath(node);
    if (p) {
      if (REQ.test(p)) return true;
      if (/^location\b/.test(p) || /^(?:document|window)\.location\b/.test(p)) return true;
      if (/^process\.argv\b/.test(p)) return true;
      if (/\.nextUrl\.searchParams\b/.test(p)) return true;
    }
    return false;
  }
  if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
    const p = node.callee ? memberPath(node.callee) : null;
    if (p && (REQ_CALL.test(p) || /\.searchParams\.get$/.test(p))) return true;
  }
  return false;
}

const NUMERIC = new Set(["Number", "parseInt", "parseFloat", "BigInt"]);
const VALIDATE = new Set(["parse", "safeParse", "validate", "validateSync", "cast"]);

/** Is `node` tainted given the set of tainted variable names in scope? */
export function isTainted(node: t.Node | null | undefined, set: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "TSAsExpression": case "TSNonNullExpression": case "TSSatisfiesExpression": case "TSTypeAssertion":
      return isTainted(node.expression, set);
    case "Identifier":
      return set.has(node.name);
    case "MemberExpression": case "OptionalMemberExpression":
      return isSourceExpr(node) || isTainted(node.object, set);
    case "TemplateLiteral":
      return node.expressions.some((e) => isTainted(e, set));
    case "BinaryExpression":
      return node.operator === "+" && (isTainted(node.left as t.Expression, set) || isTainted(node.right, set));
    case "LogicalExpression":
      return isTainted(node.left, set) || isTainted(node.right, set);
    case "ConditionalExpression":
      return isTainted(node.consequent, set) || isTainted(node.alternate, set);
    case "AwaitExpression":
      return isSourceExpr(node.argument) || isTainted(node.argument, set);
    case "CallExpression": case "OptionalCallExpression": {
      if (isSourceExpr(node)) return true;
      const callee = node.callee;
      if (t.isIdentifier(callee) && NUMERIC.has(callee.name)) return false; // numeric coercion sanitizes
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.object) && callee.object.name === "JSON" && t.isIdentifier(callee.property) && callee.property.name === "parse") {
        return node.arguments.some((a) => isTainted(a as t.Node, set)); // JSON.parse does NOT sanitize
      }
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && VALIDATE.has(callee.property.name)) return false; // schema.parse(x)
      if (t.isIdentifier(callee) && callee.name === "String") return node.arguments.some((a) => isTainted(a as t.Node, set));
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.object) && callee.object.name === "path" && t.isIdentifier(callee.property) && ["join", "resolve", "normalize"].includes(callee.property.name)) {
        return node.arguments.some((a) => isTainted(a as t.Node, set));
      }
      if (t.isMemberExpression(callee)) return isTainted(callee.object, set); // tainted.method(...) stays tainted
      return false;
    }
    default:
      return isSourceExpr(node);
  }
}

function patternNames(node: t.Node | null): string[] {
  if (!node) return [];
  if (t.isIdentifier(node)) return [node.name];
  if (t.isObjectPattern(node)) return node.properties.flatMap((p) => (t.isObjectProperty(p) ? patternNames(p.value as t.Node) : t.isRestElement(p) ? patternNames(p.argument) : []));
  if (t.isArrayPattern(node)) return node.elements.flatMap((e) => (e ? patternNames(e as t.Node) : []));
  if (t.isAssignmentPattern(node)) return patternNames(node.left);
  if (t.isRestElement(node)) return patternNames(node.argument);
  return [];
}

/** Per-function (and top-level) tainted variable sets. Last-write-wins (flow-insensitive within a
 *  scope, but a later sanitizing assignment removes taint), computed to a fixpoint. */
export function buildTaintSets(file: t.File, summaries?: Summaries): Map<t.Node, Set<string>> {
  const last = new Map<t.Node, Map<string, t.Node | null | undefined>>();
  const put = (scope: t.Node, name: string, expr: t.Node | null | undefined) => {
    const m = last.get(scope) ?? new Map();
    m.set(name, expr);
    last.set(scope, m);
  };
  const scopeOf = (path: NodePath): t.Node => path.getFunctionParent()?.node ?? file.program;
  traverse(file, {
    VariableDeclarator(path) {
      for (const n of patternNames(path.node.id)) put(scopeOf(path), n, path.node.init);
    },
    AssignmentExpression(path) {
      if (path.node.operator !== "=") return;
      for (const n of patternNames(path.node.left)) put(scopeOf(path), n, path.node.right);
    },
  });
  const sets = new Map<t.Node, Set<string>>();
  for (const [scope, m] of last) {
    const s = new Set<string>();
    sets.set(scope, s);
    for (let i = 0; i < 6; i++) {
      let changed = false;
      for (const [name, expr] of m) {
        const tainted = isTainted(expr, s) || (summaries ? returnTainted(expr, s, summaries) : false);
        if (tainted && !s.has(name)) { s.add(name); changed = true; }
        else if (!tainted && s.has(name)) { s.delete(name); changed = true; }
      }
      if (!changed) break;
    }
  }
  return sets;
}

/** Query taint for `node` at `path`, using the enclosing function's tainted set. */
export function taintedAt(path: NodePath, node: t.Node, file: t.File, sets: Map<t.Node, Set<string>>): boolean {
  const scope = path.getFunctionParent()?.node ?? file.program;
  return isTainted(node, sets.get(scope) ?? new Set());
}


/** Summary of a function's return-taint behavior (for inter-procedural data-flow). */
export interface FnSummary { params: (string | null)[]; returnsAbsolute: boolean; returnParams: Set<number>; }
export type Summaries = Map<string, FnSummary>;

function paramOf(p: t.Node): string | null {
  if (t.isIdentifier(p)) return p.name;
  if (t.isAssignmentPattern(p) && t.isIdentifier(p.left)) return p.left.name;
  return null;
}

/** Does this expression return attacker-controlled data via a known function summary? */
export function returnTainted(node: t.Node | null | undefined, set: Set<string>, summaries: Summaries): boolean {
  if (!node) return false;
  if (t.isAwaitExpression(node)) return returnTainted(node.argument, set, summaries);
  if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
    const callee = node.callee;
    const key = t.isIdentifier(callee) ? callee.name
      : (t.isMemberExpression(callee) && t.isIdentifier(callee.object) && t.isIdentifier(callee.property)) ? `${callee.object.name}.${callee.property.name}` : null;
    const s = key ? summaries.get(key) : undefined;
    if (!s) return false;
    if (s.returnsAbsolute) return true;
    return [...s.returnParams].some((i) => {
      const a = node.arguments[i] as t.Node | undefined;
      return !!a && (isTainted(a, set) || returnTainted(a, set, summaries));
    });
  }
  return false;
}

/** Build per-function return-taint summaries (fixpoint over the file; `base` seeds cross-file names). */
export function buildSummaries(file: t.File, base?: Summaries): Summaries {
  const fns = new Map<string, { node: t.Function; params: (string | null)[] }>();
  const assigns = new Map<t.Node, Array<{ names: string[]; expr: t.Node | null | undefined }>>();
  const returns = new Map<t.Node, Array<t.Node | null | undefined>>();
  const push = <V>(m: Map<t.Node, V[]>, k: t.Node, v: V) => m.set(k, [...(m.get(k) ?? []), v]);
  traverse(file, {
    Function(path) {
      let name: string | null = null;
      if (t.isFunctionDeclaration(path.node) && path.node.id) name = path.node.id.name;
      else if (path.parentPath?.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id)) name = path.parentPath.node.id.name;
      if (name) fns.set(name, { node: path.node, params: path.node.params.map((p) => paramOf(p as t.Node)) });
      if (t.isArrowFunctionExpression(path.node) && !t.isBlockStatement(path.node.body)) push(returns, path.node, path.node.body);
    },
    VariableDeclarator(path) {
      const fn = path.getFunctionParent()?.node;
      if (fn && t.isIdentifier(path.node.id)) push(assigns, fn, { names: [path.node.id.name], expr: path.node.init });
    },
    AssignmentExpression(path) {
      const fn = path.getFunctionParent()?.node;
      if (fn && path.node.operator === "=" && t.isIdentifier(path.node.left)) push(assigns, fn, { names: [path.node.left.name], expr: path.node.right });
    },
    ReturnStatement(path) {
      const fn = path.getFunctionParent()?.node;
      if (fn) push(returns, fn, path.node.argument);
    },
  });
  const sum: Summaries = new Map(base ?? []);
  const fix = (la: Array<{ names: string[]; expr: t.Node | null | undefined }>, seed: Set<string>): Set<string> => {
    const s = new Set(seed);
    for (let k = 0; k < 6; k++) {
      let ch = false;
      for (const { names, expr } of la) {
        const tt = isTainted(expr, s) || returnTainted(expr, s, sum);
        for (const n of names) { if (tt && !s.has(n)) { s.add(n); ch = true; } else if (!tt && s.has(n)) { s.delete(n); ch = true; } }
      }
      if (!ch) break;
    }
    return s;
  };
  for (let iter = 0; iter < 4; iter++) {
    let changed = false;
    for (const [name, fn] of fns) {
      const la = assigns.get(fn.node) ?? [];
      const rs = returns.get(fn.node) ?? [];
      const taintedRet = (s: Set<string>) => rs.some((r) => isTainted(r, s) || returnTainted(r, s, sum));
      const returnsAbsolute = taintedRet(fix(la, new Set()));
      const returnParams = new Set<number>();
      fn.params.forEach((pn, i) => { if (pn && taintedRet(fix(la, new Set([pn])))) returnParams.add(i); });
      const prev = sum.get(name);
      if (!prev || prev.returnsAbsolute !== returnsAbsolute || prev.returnParams.size !== returnParams.size) changed = true;
      sum.set(name, { params: fn.params, returnsAbsolute, returnParams });
    }
    if (!changed) break;
  }
  return sum;
}


const JS_SUM = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/;
const RESOLVE_EXTS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"];

/** Normalize a POSIX-style path collapsing "." and ".." segments. */
function normalizePath(p: string): string {
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  return out.join("/");
}

/** Resolve a relative import `source` (from `importerRel`) to a scanned file's rel path, or null. */
function resolveModule(source: string, importerRel: string, relSet: Set<string>): string | null {
  if (!source.startsWith(".")) return null;
  const dir = importerRel.includes("/") ? importerRel.slice(0, importerRel.lastIndexOf("/")) : "";
  const joined = normalizePath(`${dir}/${source}`);
  for (const e of RESOLVE_EXTS) if (relSet.has(joined + e)) return joined + e;
  return null;
}

export interface ImportEdge { local: string; orig: string; fromRel: string; ns: boolean; }

/** Relative-import edges from `importerRel`, resolved to the defining file. Handles named, aliased
 *  (`a as b`) and namespace (`* as ns`) imports; bare/unresolved imports are skipped (a false negative). */
export function resolveImports(file: t.File, importerRel: string, relSet: Set<string>): ImportEdge[] {
  const edges: ImportEdge[] = [];
  traverse(file, {
    ImportDeclaration(path) {
      const fromRel = resolveModule(path.node.source.value, importerRel, relSet);
      if (!fromRel) return;
      for (const sp of path.node.specifiers) {
        if (t.isImportSpecifier(sp)) edges.push({ local: sp.local.name, orig: t.isIdentifier(sp.imported) ? sp.imported.name : sp.imported.value, fromRel, ns: false });
        else if (t.isImportNamespaceSpecifier(sp)) edges.push({ local: sp.local.name, orig: "*", fromRel, ns: true });
      }
    },
  });
  return edges;
}

/** Per-file return-taint summaries with REAL cross-file resolution: relative imports are resolved to the
 *  defining file (named + aliased + namespace), and a cross-file fixpoint propagates multi-hop chains. */
export function crossFileSummaries(files: SourceFile[]): Map<string, Summaries> {
  const parsed = new Map<string, t.File>();
  const local = new Map<string, Summaries>();
  for (const f of files) {
    if (!JS_SUM.test(f.rel)) continue;
    const ast = parseFile(f.content, f.rel);
    if (!ast) continue;
    parsed.set(f.rel, ast);
    local.set(f.rel, buildSummaries(ast));
  }
  const relSet = new Set(parsed.keys());
  const edges = new Map<string, ImportEdge[]>();
  for (const [rel, ast] of parsed) edges.set(rel, resolveImports(ast, rel, relSet));
  const eff = new Map<string, Summaries>();
  for (const [rel, s] of local) eff.set(rel, new Map(s));
  for (let iter = 0; iter < 8; iter++) {
    let changed = false;
    for (const [rel, ast] of parsed) {
      const base: Summaries = new Map(local.get(rel));
      for (const e of edges.get(rel) ?? []) {
        const fromEff = eff.get(e.fromRel);
        if (!fromEff) continue;
        if (e.ns) for (const [n, s] of fromEff) base.set(`${e.local}.${n}`, s);
        else { const s = fromEff.get(e.orig); if (s) base.set(e.local, s); }
      }
      const ne = buildSummaries(ast, base);
      const prev = eff.get(rel);
      if (!prev || prev.size !== ne.size || [...ne].some(([k, v]) => { const p = prev.get(k); return !p || p.returnsAbsolute !== v.returnsAbsolute || p.returnParams.size !== v.returnParams.size; })) changed = true;
      eff.set(rel, ne);
    }
    if (!changed) break;
  }
  return eff;
}
