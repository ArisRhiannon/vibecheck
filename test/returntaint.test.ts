import { test, expect, describe } from "bun:test";
import { astFindings } from "../src/index";

const run = (code: string, rel = "a.ts") => astFindings([{ path: rel, rel, content: code }]);
const has = (code: string, id: string) => run(code).some((f) => f.ruleId === id);

describe("return-taint (intra-file inter-procedural)", () => {
  test("a value returned from a source-reading helper taints a downstream sink", () => {
    expect(has("function getInput(){ return req.body.x; }\nconst v = getInput();\ndb.query(v);", "VC-SQLI")).toBe(true);
  });
  test("a pass-through helper carries its argument's taint to the return value", () => {
    expect(has("function wrap(x){ return x; }\nconst v = wrap(req.body.id);\ndb.query(v);", "VC-SQLI")).toBe(true);
  });
  test("a helper that returns a constant does not taint", () => {
    expect(run("function getId(){ return 42; }\nconst v = getId();\ndb.query(v);").length).toBe(0);
  });
  test("a sanitizing helper (returns Number(x)) does not taint", () => {
    expect(has("function toId(x){ return Number(x); }\nconst v = toId(req.body.id);\ndb.query(v);", "VC-SQLI")).toBe(false);
  });
});
