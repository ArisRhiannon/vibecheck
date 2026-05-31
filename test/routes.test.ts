import { test, expect, describe } from "bun:test";
import { routeFindings, type SourceFile } from "../src/index";

const sf = (content: string, rel = "a.ts"): SourceFile => ({ path: `/x/${rel}`, rel, content });
const has = (c: string, id: string, rel = "a.ts") => routeFindings([sf(c, rel)]).some((f) => f.ruleId === id);

describe("AC4.1 route auth", () => {
  test("Express handler without auth fires; with middleware does not", () => {
    expect(has('app.get("/users", (req, res) => { res.json(users); })', "VC-ROUTE-NO-AUTH")).toBe(true);
    expect(has('app.get("/users", requireAuth, (req, res) => { res.json(users); })', "VC-ROUTE-NO-AUTH")).toBe(false);
  });
  test("Next route handler without/with session", () => {
    expect(has("export async function GET(req) { return Response.json(data); }", "VC-ROUTE-NO-AUTH", "app/api/users/route.ts")).toBe(true);
    expect(has("export async function GET(req) { const session = await getServerSession(); return Response.json(data); }", "VC-ROUTE-NO-AUTH", "app/api/users/route.ts")).toBe(false);
  });
});

describe("AC4.2 input validation", () => {
  test("reading body without a validator fires; with zod import does not", () => {
    expect(has("app.post('/x', (req,res)=>{ const n = req.body.name; save(n); })", "VC-INPUT-NO-VALIDATION")).toBe(true);
    expect(has("import { z } from 'zod';\napp.post('/x', (req,res)=>{ const n = req.body.name; })", "VC-INPUT-NO-VALIDATION")).toBe(false);
  });
});

describe("AC4.3/4.4/4.5 leaky config", () => {
  test("NEXT_PUBLIC secret fires; anon key does not", () => {
    expect(has("const k = process.env.NEXT_PUBLIC_API_SECRET;", "VC-NEXT-PUBLIC-SECRET")).toBe(true);
    expect(has("const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;", "VC-NEXT-PUBLIC-SECRET")).toBe(false);
  });
  test("Supabase service_role: critical in client component, high otherwise", () => {
    const cli = routeFindings([sf('"use client";\nconst c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);')]);
    expect(cli.find((f) => f.ruleId === "VC-SUPABASE-SERVICE-ROLE")?.severity).toBe("critical");
    const srv = routeFindings([sf("const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);")]);
    expect(srv.find((f) => f.ruleId === "VC-SUPABASE-SERVICE-ROLE")?.severity).toBe("high");
  });
  test("stack trace exposure fires", () => {
    expect(has("app.use((err,req,res,next)=>{ res.send(err.stack); })", "VC-STACK-EXPOSURE")).toBe(true);
  });
});
