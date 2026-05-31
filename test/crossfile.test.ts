import { test, expect, describe } from "bun:test";
import { astFindings, interprocFindings, crossFileSummaries } from "../src/index";

const sf = (rel: string, content: string) => ({ path: rel, rel, content });

describe("cross-file (by imported name) taint", () => {
  test("return-taint across files: an imported source-returning helper taints a sink", () => {
    const files = [sf("util.ts", "export function getInput(){ return req.body.x; }"), sf("app.ts", "import { getInput } from './util';\nconst v = getInput();\ndb.query(v);")];
    const f = astFindings(files, crossFileSummaries(files));
    expect(f.some((x) => x.ruleId === "VC-SQLI" && x.file === "app.ts")).toBe(true);
  });
  test("param-sink across files: an imported helper whose param reaches a sink fires at the call site", () => {
    const files = [sf("db.ts", "export function runRaw(s){ db.query(s); }"), sf("app.ts", "import { runRaw } from './db';\nrunRaw(req.body.x);")];
    const f = interprocFindings(files, crossFileSummaries(files));
    expect(f.some((x) => x.ruleId === "VC-SQLI" && x.file === "app.ts")).toBe(true);
  });
  test("no cross-file taint when the helper is referenced by bare name without importing it", () => {
    const files = [sf("db.ts", "export function runRaw(s){ db.query(s); }"), sf("app.ts", "runRaw(req.body.x);")];
    const f = interprocFindings(files, crossFileSummaries(files));
    expect(f.some((x) => x.ruleId === "VC-SQLI")).toBe(false);
  });
});
