import { type SourceFile, type Finding, type Severity, type Confidence } from "./types";
import { parseFile, traverse, t, type NodePath } from "./ast";
import { buildTaintSets, buildSummaries, taintedAt, isSourceExpr, memberPath, type Summaries } from "./taint";

const JS = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/;
const CP = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync"]);
const FS_SINK = new Set(["readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "createReadStream", "createWriteStream", "unlink", "unlinkSync", "readdir", "readdirSync", "rm", "rmSync", "open", "openSync"]);
const AUTH = /req\.user|requireauth|isauthenticated|authenticate|authoriz|ensureauth|getserversession|getsession|getuser|verifytoken|passport|withauth|clerk|currentuser|requirelogin|checkauth|\bauth\b/i;
const VALIDATOR_IMPORT = /(?:from|require\s*\(?)\s*['"](?:zod|joi|yup|valibot|class-validator|@hapi\/joi|superstruct|ajv|@sinclair\/typebox)['"]/;

function literalish(node: t.Node): boolean {
  return t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node) || (t.isTemplateLiteral(node) && node.expressions.length === 0);
}

/** Leftmost string-literal prefix of a `+`/template expression, if any (for relative-path detection). */
function leadingLiteral(node: t.Node): string | null {
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node) && node.quasis[0]) return node.quasis[0].value.cooked ?? node.quasis[0].value.raw;
  if (t.isBinaryExpression(node) && node.operator === "+") return leadingLiteral(node.left as t.Node);
  return null;
}
/** A redirect target that starts with a fixed "/path" (not "//host") stays same-site → not an open redirect. */
function isRelativeRedirect(node: t.Node): boolean {
  const p = leadingLiteral(node);
  return p !== null && p.startsWith("/") && !p.startsWith("//");
}

/** Find an object-expression argument and return a property's value node by key, if present. */
function prop(obj: t.Node | undefined, key: string): t.Node | undefined {
  if (!obj || !t.isObjectExpression(obj)) return undefined;
  for (const p of obj.properties) {
    if (t.isObjectProperty(p) && ((t.isIdentifier(p.key) && p.key.name === key) || (t.isStringLiteral(p.key) && p.key.value === key))) return p.value as t.Node;
  }
  return undefined;
}
function isTrue(node: t.Node | undefined): boolean {
  return !!node && t.isBooleanLiteral(node) && node.value === true;
}

/** AST + taint analysis of JS/TS/JSX/TSX files. Findings carry confidence (taint-backed = high). */
export function astFindings(files: SourceFile[], summariesByRel?: Map<string, Summaries>): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    if (!JS.test(f.rel)) continue;
    const ast = parseFile(f.content, f.rel);
    if (!ast) continue;
    const sets = buildTaintSets(ast, summariesByRel?.get(f.rel) ?? buildSummaries(ast));
    const lines = f.content.split("\n");
    const hasValidator = VALIDATOR_IMPORT.test(f.content);
    const isNextRoute = /(?:^|\/)route\.(?:t|j)sx?$/.test(f.rel);

    const mk = (node: t.Node, ruleId: string, severity: Severity, confidence: Confidence, message: string, remediation: string): void => {
      const line = node.loc?.start.line ?? 1;
      out.push({ ruleId, severity, confidence, file: f.rel, line, col: (node.loc?.start.column ?? 0) + 1, message, snippet: (lines[line - 1] ?? "").trim(), remediation });
    };

    traverse(ast, {
      CallExpression(path) {
        const node = path.node;
        const callee = node.callee;
        const arg0 = node.arguments[0] as t.Node | undefined;
        const cp = memberPath(callee as t.Node);
        const tainted = (n: t.Node | undefined) => !!n && taintedAt(path, n, ast, sets);

        // eval(x)
        if (t.isIdentifier(callee) && callee.name === "eval" && arg0 && !literalish(arg0)) {
          mk(node, "VC-RCE-EVAL", "critical", tainted(arg0) ? "high" : "medium", "eval() on a non-literal value (remote code execution)", "Never eval dynamic input; use JSON.parse or an explicit dispatch table.");
        }
        // child_process exec/spawn (real, not ORM .exec())
        const isCP = (t.isIdentifier(callee) && CP.has(callee.name)) ||
          (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && CP.has(callee.property.name) && t.isIdentifier(callee.object) && (callee.object.name === "child_process" || callee.object.name === "cp"));
        if (isCP && arg0 && !literalish(arg0)) {
          mk(node, "VC-RCE-CHILD-PROCESS", "high", tainted(arg0) ? "high" : "medium", "child_process runs a non-literal command (command injection)", "Use execFile with a fixed program + args array; validate inputs.");
        }
        // SQL raw APIs + .query/.execute
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
          const m = callee.property.name;
          const rawApi = m === "raw" || m === "$queryRawUnsafe" || m === "$executeRawUnsafe";
          const queryApi = m === "query" || m === "execute";
          const objName = t.isIdentifier(callee.object) ? callee.object.name : "";
          const callSrc = f.content.slice(node.start ?? 0, node.end ?? 0);
          const looksDb = /^(?:db|sql|conn|connection|pool|client|knex|sequelize|prisma|pg|mysql|mysql2|sqlite|database|datasource|ds|orm|tx|trx|qb|repo|repository)$/i.test(objName) || /\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(callSrc);
          if ((rawApi || (queryApi && looksDb)) && arg0 && !literalish(arg0)) {
            if (tainted(arg0)) mk(node, "VC-SQLI", "critical", "high", `SQL via ${m}() built from tainted input (SQL injection)`, "Use parameterized queries / bound placeholders; never interpolate user input.");
            else if (t.isTemplateLiteral(arg0) || (t.isBinaryExpression(arg0) && arg0.operator === "+")) mk(node, "VC-SQLI", "medium", "review", `SQL via ${m}() built by interpolation/concatenation (verify the values are not user-controlled)`, "Prefer parameterized queries / bound placeholders.");
          }
        }
        // SSRF: fetch/axios/got/http(s).get with tainted URL
        const ssrf = (t.isIdentifier(callee) && ["fetch", "axios", "got", "request"].includes(callee.name)) ||
          (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && ["get", "post", "request"].includes(callee.property.name) && t.isIdentifier(callee.object) && ["axios", "http", "https", "got"].includes(callee.object.name));
        if (ssrf && tainted(arg0)) mk(node, "VC-SSRF", "high", "high", "server-side request to a tainted URL (SSRF)", "Validate the URL against an allowlist of hosts; block internal/metadata IPs.");
        // Path traversal: fs.* with tainted path
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && FS_SINK.has(callee.property.name) && tainted(arg0)) {
          mk(node, "VC-PATH-TRAVERSAL", "high", "high", "filesystem path built from tainted input (path traversal)", "Resolve against a fixed base dir and reject paths that escape it (no '..').");
        }
        // Open redirect
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && (callee.property.name === "redirect" || callee.property.name === "location") && tainted(arg0) && arg0 && !isRelativeRedirect(arg0)) {
          mk(node, "VC-OPEN-REDIRECT", "medium", "high", "redirect target is tainted (open redirect)", "Redirect only to a fixed allowlist of paths/hosts.");
        }
        // document.write(tainted) → XSS
        if ((cp === "document.write" || cp === "document.writeln") && tainted(arg0)) mk(node, "VC-XSS-DOM", "high", "high", "document.write()/writeln() with tainted input (DOM XSS)", "Avoid document.write; set textContent or sanitize HTML.");
        // jwt.verify options
        if (cp === "jwt.verify") {
          const opts = node.arguments[2] as t.Node | undefined;
          const algs = prop(opts, "algorithms");
          if (algs && t.isArrayExpression(algs) && algs.elements.some((e) => e && t.isStringLiteral(e) && e.value.toLowerCase() === "none")) {
            mk(node, "VC-JWT-NONE", "critical", "high", "JWT 'none' algorithm permitted (signature bypass)", "Pin a strong algorithm and reject 'none'.");
          } else if (!algs) {
            mk(node, "VC-JWT-UNPINNED", "high", "medium", "jwt.verify() without pinned algorithms (algorithm confusion)", "Pass { algorithms: ['HS256'] }.");
          }
        }
        // CORS options
        if (t.isIdentifier(callee) && callee.name === "cors") {
          const origin = prop(arg0, "origin");
          if (origin && t.isStringLiteral(origin) && origin.value === "*") {
            const creds = isTrue(prop(arg0, "credentials"));
            mk(node, "VC-CORS-WILDCARD", creds ? "high" : "medium", "high", `CORS allows any origin ('*')${creds ? " with credentials" : ""}`, "Restrict origin to an explicit allowlist; never combine '*' with credentials.");
          }
        }
        // Insecure auth/session cookie
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && callee.property.name === "cookie" && arg0 && t.isStringLiteral(arg0) && /sess|token|auth|sid|jwt/i.test(arg0.value)) {
          const opts = node.arguments[2] as t.Node | undefined;
          if (!isTrue(prop(opts, "httpOnly")) || !isTrue(prop(opts, "secure"))) {
            mk(node, "VC-COOKIE-INSECURE", "high", "high", `auth/session cookie "${arg0.value}" set without httpOnly + secure`, "Set { httpOnly: true, secure: true, sameSite: 'lax' }.");
          }
        }
        // Error stack returned to client
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && ["send", "json", "end"].includes(callee.property.name)) {
          const a = arg0;
          if (a && memberPath(a)?.endsWith(".stack")) mk(node, "VC-STACK-EXPOSURE", "medium", "high", "error stack trace sent in the HTTP response", "Log stacks server-side; return a generic message.");
        }
        // Express route handler without auth (review)
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.object) && /^(?:app|router|fastify|server)$/.test(callee.object.name) && t.isIdentifier(callee.property) && ["get", "post", "put", "delete", "patch", "all"].includes(callee.property.name)) {
          const src = f.content.slice(node.start ?? 0, node.end ?? 0);
          if (!AUTH.test(src)) mk(node, "VC-ROUTE-NO-AUTH", "review", "review", "route handler with no visible authentication/authorization check", "Confirm the endpoint is public; otherwise add an auth middleware / session check.");
        }
      },
      NewExpression(path) {
        const node = path.node;
        const arg0 = node.arguments[0] as t.Node | undefined;
        if (t.isIdentifier(node.callee) && node.callee.name === "Function" && arg0 && !literalish(arg0)) {
          mk(node, "VC-RCE-EVAL", "critical", taintedAt(path, arg0, ast, sets) ? "high" : "medium", "new Function() on a non-literal value (remote code execution)", "Never build functions from dynamic input.");
        }
      },
      AssignmentExpression(path) {
        const node = path.node;
        if (node.operator !== "=") return;
        const left = node.left;
        if (t.isMemberExpression(left) && t.isIdentifier(left.property) && (left.property.name === "innerHTML" || left.property.name === "outerHTML")) {
          if (!literalish(node.right)) mk(node, "VC-XSS-DOM", "high", taintedAt(path, node.right, ast, sets) ? "high" : "medium", `${left.property.name} assigned non-literal HTML (DOM XSS)`, "Use textContent, or sanitize with DOMPurify before assigning HTML.");
        }
      },
      JSXAttribute(path) {
        const node = path.node;
        if (t.isJSXIdentifier(node.name) && node.name.name === "dangerouslySetInnerHTML" && node.value && t.isJSXExpressionContainer(node.value)) {
          const html = t.isObjectExpression(node.value.expression) ? prop(node.value.expression, "__html") : undefined;
          if (html && !literalish(html)) mk(node, "VC-XSS-REACT", "high", taintedAt(path, html, ast, sets) ? "high" : "medium", "dangerouslySetInnerHTML with non-literal HTML (XSS)", "Sanitize with DOMPurify, or render text instead of raw HTML.");
        }
      },
      FunctionDeclaration(path) {
        if (!isNextRoute) return;
        const decl = path.node;
        if (decl.id && ["GET", "POST", "PUT", "DELETE", "PATCH"].includes(decl.id.name)) {
          const src = f.content.slice(decl.start ?? 0, decl.end ?? 0);
          if (!AUTH.test(src)) mk(decl, "VC-ROUTE-NO-AUTH", "review", "review", `Next.js ${decl.id.name} handler with no visible auth/session check`, "Gate the route with getServerSession()/auth()/middleware if not public.");
        }
      },
    });

    // Input read without a schema validator imported (one advisory per file)
    if (!hasValidator) {
      let readNode: t.Node | null = null;
      traverse(ast, {
        MemberExpression(path) {
          if (readNode) return;
          const p = memberPath(path.node);
          if (p && /^(?:req|request)\.(?:body|query|params)\b/.test(p)) readNode = path.node;
        },
      });
      if (readNode) mk(readNode, "VC-INPUT-NO-VALIDATION", "medium", "medium", "request input is read without a schema validator imported (zod/joi/yup/valibot/…)", "Validate req body/query/params against a schema before use.");
    }
  }
  return out;
}
