import { test, expect, describe } from "bun:test";
import { astFindings, type SourceFile, type Finding } from "../src/index";

const run = (content: string, rel = "a.ts"): Finding[] => astFindings([{ path: `/x/${rel}`, rel, content }]);
const has = (content: string, id: string, rel = "a.ts") => run(content, rel).some((f) => f.ruleId === id);
const find = (content: string, id: string, rel = "a.ts") => run(content, rel).find((f) => f.ruleId === id);

describe("RCE (taint-backed)", () => {
  test("eval/child_process: tainted=high, non-literal=medium, literal/ORM=none", () => {
    expect(find("app.post('/r', (req,res)=>{ eval(req.body.code); })", "VC-RCE-EVAL")?.confidence).toBe("high");
    expect(find("function f(x){ eval(x); }", "VC-RCE-EVAL")?.confidence).toBe("medium");
    expect(has('eval("2 + 2")', "VC-RCE-EVAL")).toBe(false);
    expect(find("const cmd = req.body.cmd; execSync(cmd);", "VC-RCE-CHILD-PROCESS")?.confidence).toBe("high");
    expect(has("const u = await User.find().exec();", "VC-RCE-CHILD-PROCESS")).toBe(false);
    expect(has('execSync("ls -la")', "VC-RCE-CHILD-PROCESS")).toBe(false);
  });
});

describe("SQL injection via abstracted raw APIs (the v0.1 blind spot)", () => {
  test("knex.raw / $queryRawUnsafe with tainted input = high; parameterized/tagged = none", () => {
    expect(find("knex.raw(req.query.q)", "VC-SQLI")?.confidence).toBe("high");
    expect(find("const q = req.query.id; prisma.$queryRawUnsafe(q)", "VC-SQLI")?.confidence).toBe("high");
    expect(has('db.query("SELECT * FROM u WHERE id = $1", [id])', "VC-SQLI")).toBe(false);
    expect(has("sql`SELECT * FROM u WHERE id = ${id}`", "VC-SQLI")).toBe(false); // tagged template = parameterized
  });
});

describe("XSS", () => {
  test("dangerouslySetInnerHTML + innerHTML with tainted/non-literal", () => {
    expect(find("const el = <div dangerouslySetInnerHTML={{ __html: req.query.html }} />;", "VC-XSS-REACT", "a.tsx")?.confidence).toBe("high");
    expect(has('const el = <div dangerouslySetInnerHTML={{ __html: "<b>ok</b>" }} />;', "VC-XSS-REACT", "a.tsx")).toBe(false);
    expect(find("node.innerHTML = req.body.html;", "VC-XSS-DOM")?.confidence).toBe("high");
    expect(has('node.innerHTML = "<b>static</b>";', "VC-XSS-DOM")).toBe(false);
  });
});

describe("SSRF / path traversal / open redirect (taint-backed)", () => {
  test("tainted sinks fire high; constants do not", () => {
    expect(find("fetch(req.query.url)", "VC-SSRF")?.confidence).toBe("high");
    expect(has('fetch("https://api.example.com/x")', "VC-SSRF")).toBe(false);
    expect(find("fs.readFile(path.join(dir, req.query.f), cb)", "VC-PATH-TRAVERSAL")?.confidence).toBe("high");
    expect(has('fs.readFile("./config.json", cb)', "VC-PATH-TRAVERSAL")).toBe(false);
    expect(find("res.redirect(req.query.next)", "VC-OPEN-REDIRECT")?.confidence).toBe("high");
  });
});

describe("config misconfig (AST of options objects)", () => {
  test("CORS / JWT / cookie", () => {
    expect(find('app.use(cors({ origin: "*", credentials: true }))', "VC-CORS-WILDCARD")?.severity).toBe("high");
    expect(has('cors({ origin: "https://app.example.com" })', "VC-CORS-WILDCARD")).toBe(false);
    expect(has('jwt.verify(t, s, { algorithms: ["none"] })', "VC-JWT-NONE")).toBe(true);
    expect(has("jwt.verify(t, s)", "VC-JWT-UNPINNED")).toBe(true);
    expect(has('jwt.verify(t, s, { algorithms: ["HS256"] })', "VC-JWT-UNPINNED")).toBe(false);
    expect(has('res.cookie("session", v, { httpOnly: true })', "VC-COOKIE-INSECURE")).toBe(true);
    expect(has('res.cookie("session", v, { httpOnly: true, secure: true })', "VC-COOKIE-INSECURE")).toBe(false);
  });
});

describe("route auth + input validation + stack", () => {
  test("no-auth fires (review), middleware suppresses; validator import suppresses", () => {
    expect(find("app.get('/x', (req,res)=>{ res.json(1); })", "VC-ROUTE-NO-AUTH")?.confidence).toBe("review");
    expect(has("app.get('/x', requireAuth, (req,res)=>{ res.json(1); })", "VC-ROUTE-NO-AUTH")).toBe(false);
    expect(has("app.post('/x',(req,res)=>{ const n = req.body.name; })", "VC-INPUT-NO-VALIDATION")).toBe(true);
    expect(has("import { z } from 'zod';\napp.post('/x',(req,res)=>{ const n = req.body.name; })", "VC-INPUT-NO-VALIDATION")).toBe(false);
    expect(has("app.use((e,req,res,nx)=>{ res.send(e.stack); })", "VC-STACK-EXPOSURE")).toBe(true);
  });
});
