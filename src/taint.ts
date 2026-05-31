import { traverse, t, type NodePath } from "./ast";

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

/** Per-function (and top-level) sets of tainted variable names, computed to a fixpoint. */
export function buildTaintSets(file: t.File): Map<t.Node, Set<string>> {
  const recs = new Map<t.Node, { names: string[]; expr: t.Node | null | undefined }[]>();
  const add = (scope: t.Node, rec: { names: string[]; expr: t.Node | null | undefined }) => {
    const list = recs.get(scope) ?? [];
    list.push(rec);
    recs.set(scope, list);
  };
  const scopeOf = (path: NodePath): t.Node => path.getFunctionParent()?.node ?? file.program;
  traverse(file, {
    VariableDeclarator(path) {
      const names = patternNames(path.node.id);
      if (names.length) add(scopeOf(path), { names, expr: path.node.init });
    },
    AssignmentExpression(path) {
      if (path.node.operator !== "=") return;
      const names = patternNames(path.node.left);
      if (names.length) add(scopeOf(path), { names, expr: path.node.right });
    },
  });
  const sets = new Map<t.Node, Set<string>>();
  for (const [scope, list] of recs) {
    const s = new Set<string>();
    sets.set(scope, s);
    for (let i = 0; i < 4; i++) {
      let changed = false;
      for (const r of list) {
        if (isTainted(r.expr, s)) for (const n of r.names) if (!s.has(n)) { s.add(n); changed = true; }
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
