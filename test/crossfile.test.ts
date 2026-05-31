import { test, expect, describe } from "bun:test";
import { astFindings, interprocFindings, crossFileSummaries } from "../src/index";

const sf = (rel: string, content: string) => ({ path: rel, rel, content });
const sqlOnApp = (files: ReturnType<typeof sf>[], fn = astFindings) => fn(files, crossFileSummaries(files)).some((x) => x.ruleId === "VC-SQLI" && x.file === "app.ts");

describe("cross-file taint with real module resolution", () => {
  test("named import: source-returning helper taints a sink", () => {
    expect(sqlOnApp([sf("util.ts", "export function getInput(){ return req.body.x; }"), sf("app.ts", "import { getInput } from './util';\nconst v = getInput();\ndb.query(v);")])).toBe(true);
  });
  test("aliased import (`a as b`) is resolved", () => {
    expect(sqlOnApp([sf("util.ts", "export function getInput(){ return req.body.x; }"), sf("app.ts", "import { getInput as gi } from './util';\nconst v = gi();\ndb.query(v);")])).toBe(true);
  });
  test("namespace import (`* as ns`) return-taint is resolved", () => {
    expect(sqlOnApp([sf("util.ts", "export function getInput(){ return req.body.x; }"), sf("app.ts", "import * as u from './util';\nconst v = u.getInput();\ndb.query(v);")])).toBe(true);
  });
  test("param→sink across files (named + namespace)", () => {
    expect(sqlOnApp([sf("db.ts", "export function runRaw(s){ db.query(s); }"), sf("app.ts", "import { runRaw } from './db';\nrunRaw(req.body.x);")], interprocFindings)).toBe(true);
    expect(sqlOnApp([sf("db.ts", "export function runRaw(s){ db.query(s); }"), sf("app.ts", "import * as d from './db';\nd.runRaw(req.body.x);")], interprocFindings)).toBe(true);
  });
  test("multi-hop chain across THREE files", () => {
    const files = [
      sf("c.ts", "export function getInput(){ return req.body.x; }"),
      sf("b.ts", "import { getInput } from './c';\nexport function wrap(){ return getInput(); }"),
      sf("app.ts", "import { wrap } from './b';\nconst v = wrap();\ndb.query(v);"),
    ];
    expect(sqlOnApp(files)).toBe(true);
  });
  test("precise resolution: import the TAINTED same-name helper → fires; the SAFE one → does not", () => {
    const tainted = sf("tainted.ts", "export function getData(){ return req.body.x; }");
    const safe = sf("safe.ts", "export function getData(){ return 42; }");
    expect(sqlOnApp([tainted, safe, sf("app.ts", "import { getData } from './tainted';\nconst v = getData();\ndb.query(v);")])).toBe(true);
    expect(sqlOnApp([tainted, safe, sf("app.ts", "import { getData } from './safe';\nconst v = getData();\ndb.query(v);")])).toBe(false);
  });
  test("a bare-name call without an import is not resolved cross-file", () => {
    expect(sqlOnApp([sf("db.ts", "export function runRaw(s){ db.query(s); }"), sf("app.ts", "runRaw(req.body.x);")], interprocFindings)).toBe(false);
  });
});
