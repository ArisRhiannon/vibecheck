import { type SourceFile, type Finding, type Severity } from "./types";
import { parseFile, traverse, t } from "./ast";
import { buildTaintSets, buildSummaries, taintedAt, isTainted, isSourceExpr, resolveImports, type Summaries } from "./taint";

const JS = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/;
const CP = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync"]);
const FS_SINK = new Set(["readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "createReadStream", "createWriteStream", "unlink", "unlinkSync", "readdir", "readdirSync", "rm", "rmSync", "open", "openSync"]);
const DB = /^(?:db|sql|conn|connection|pool|client|knex|sequelize|prisma|pg|mysql|mysql2|sqlite|database|datasource|ds|orm|tx|trx|qb|repo|repository)$/i;

interface Sink { arg: t.Node | undefined; ruleId: string; severity: Severity; sink: string; fix: string; }

/** Which dangerous sink (if any) this call is — independent of taint. Mirrors the wrap-prone subset of analyze2. */
function matchSink(node: t.CallExpression): Sink | null {
  const callee = node.callee;
  const a0 = node.arguments[0] as t.Node | undefined;
  if (t.isIdentifier(callee) && callee.name === "eval") return { arg: a0, ruleId: "VC-RCE-EVAL", severity: "critical", sink: "eval()", fix: "Never eval dynamic input; use an explicit dispatch table." };
  const isCP = (t.isIdentifier(callee) && CP.has(callee.name)) || (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && CP.has(callee.property.name) && t.isIdentifier(callee.object) && (callee.object.name === "child_process" || callee.object.name === "cp"));
  if (isCP) return { arg: a0, ruleId: "VC-RCE-CHILD-PROCESS", severity: "high", sink: "child_process", fix: "Use execFile with a fixed program + args array; validate inputs." };
  if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
    const m = callee.property.name;
    const rawApi = m === "raw" || m === "$queryRawUnsafe" || m === "$executeRawUnsafe";
    const queryApi = m === "query" || m === "execute";
    const looksDb = t.isIdentifier(callee.object) && DB.test(callee.object.name);
    if (rawApi || (queryApi && looksDb)) return { arg: a0, ruleId: "VC-SQLI", severity: "critical", sink: `${m}()`, fix: "Use parameterized queries / bound placeholders." };
    if (FS_SINK.has(m)) return { arg: a0, ruleId: "VC-PATH-TRAVERSAL", severity: "high", sink: "fs path", fix: "Resolve against a fixed base dir and reject '..'." };
    if (["get", "post", "request"].includes(m) && t.isIdentifier(callee.object) && ["axios", "http", "https", "got"].includes(callee.object.name)) return { arg: a0, ruleId: "VC-SSRF", severity: "high", sink: "outbound request", fix: "Validate the URL against a host allowlist." };
  }
  if (t.isIdentifier(callee) && ["fetch", "axios", "got"].includes(callee.name)) return { arg: a0, ruleId: "VC-SSRF", severity: "high", sink: "outbound request", fix: "Validate the URL against a host allowlist." };
  return null;
}

function paramName(p: t.Node): string | null {
  if (t.isIdentifier(p)) return p.name;
  if (t.isAssignmentPattern(p) && t.isIdentifier(p.left)) return p.left.name;
  return null;
}

function fixpoint(assigns: Array<{ names: string[]; expr: t.Node | null | undefined }>, seed: Set<string>): Set<string> {
  const s = new Set(seed);
  for (let k = 0; k < 6; k++) {
    let changed = false;
    for (const { names, expr } of assigns) {
      const tt = isTainted(expr, s);
      for (const n of names) {
        if (tt && !s.has(n)) { s.add(n); changed = true; }
        else if (!tt && s.has(n)) { s.delete(n); changed = true; }
      }
    }
    if (!changed) break;
  }
  return s;
}

type ParamSink = { param: number; hit: Sink };

/** Intra-file AND cross-file (by imported name) inter-procedural findings: a call passes attacker input
 *  into a helper whose parameter provably reaches a dangerous sink (sanitizers respected). Taint-backed → high. */
export function interprocFindings(files: SourceFile[], summariesByRel?: Map<string, Summaries>): Finding[] {
  const out: Finding[] = [];
  const infos: Array<{ f: SourceFile; ast: t.File; summary: Map<string, ParamSink[]> }> = [];

  for (const f of files) {
    if (!JS.test(f.rel)) continue;
    const ast = parseFile(f.content, f.rel);
    if (!ast) continue;
    const fns = new Map<string, { node: t.Function; params: (string | null)[] }>();
    const assignsByFn = new Map<t.Node, Array<{ names: string[]; expr: t.Node | null | undefined }>>();
    const sinksByFn = new Map<t.Node, Sink[]>();
    const add = <V>(map: Map<t.Node, V[]>, k: t.Node, v: V) => map.set(k, [...(map.get(k) ?? []), v]);
    traverse(ast, {
      Function(path) {
        let name: string | null = null;
        if (t.isFunctionDeclaration(path.node) && path.node.id) name = path.node.id.name;
        else if (path.parentPath?.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id)) name = path.parentPath.node.id.name;
        if (name) fns.set(name, { node: path.node, params: path.node.params.map((p) => paramName(p as t.Node)) });
      },
      VariableDeclarator(path) { const fn = path.getFunctionParent()?.node; if (fn && t.isIdentifier(path.node.id)) add(assignsByFn, fn, { names: [path.node.id.name], expr: path.node.init }); },
      AssignmentExpression(path) { const fn = path.getFunctionParent()?.node; if (fn && path.node.operator === "=" && t.isIdentifier(path.node.left)) add(assignsByFn, fn, { names: [path.node.left.name], expr: path.node.right }); },
      CallExpression(path) { const fn = path.getFunctionParent()?.node; const hit = matchSink(path.node); if (fn && hit) add(sinksByFn, fn, hit); },
    });
    const summary = new Map<string, ParamSink[]>();
    for (const [name, fn] of fns) {
      const sinks = sinksByFn.get(fn.node) ?? [];
      const assigns = assignsByFn.get(fn.node) ?? [];
      const ps: ParamSink[] = [];
      fn.params.forEach((pn, i) => { if (!pn) return; const set = fixpoint(assigns, new Set([pn])); for (const hit of sinks) if (isTainted(hit.arg, set)) ps.push({ param: i, hit }); });
      if (ps.length) summary.set(name, ps);
    }
    infos.push({ f, ast, summary });
  }
  const relSet = new Set(infos.map((i) => i.f.rel));
  const summaryByRel = new Map(infos.map((i) => [i.f.rel, i.summary]));

  for (const { f, ast, summary } of infos) {
    const effective = new Map(summary);
    for (const e of resolveImports(ast, f.rel, relSet)) {
      const from = summaryByRel.get(e.fromRel);
      if (!from) continue;
      if (e.ns) { for (const [n, ps] of from) effective.set(`${e.local}.${n}`, ps); }
      else { const ps = from.get(e.orig); if (ps) effective.set(e.local, ps); }
    }
    if (!effective.size) continue;
    const sets = buildTaintSets(ast, summariesByRel?.get(f.rel) ?? buildSummaries(ast));
    const lines = f.content.split("\n");
    traverse(ast, {
      CallExpression(path) {
        const callee = path.node.callee;
        const key = t.isIdentifier(callee) ? callee.name
          : (t.isMemberExpression(callee) && t.isIdentifier(callee.object) && t.isIdentifier(callee.property)) ? `${callee.object.name}.${callee.property.name}` : null;
        const ps = key ? effective.get(key) : undefined;
        if (!ps) return;
        for (const { param, hit } of ps) {
          const arg = path.node.arguments[param] as t.Node | undefined;
          if (!arg || !(isSourceExpr(arg) || taintedAt(path, arg, ast, sets))) continue;
          const line = path.node.loc?.start.line ?? 1;
          out.push({ ruleId: hit.ruleId, severity: hit.severity, confidence: "high", file: f.rel, line,
            col: (path.node.loc?.start.column ?? 0) + 1,
            message: `tainted input flows through ${key}() into ${hit.sink} (inter-procedural)`,
            snippet: (lines[line - 1] ?? "").trim(), remediation: hit.fix });
        }
      },
    });
  }
  return out;
}
