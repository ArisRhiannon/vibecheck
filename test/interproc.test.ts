import { test, expect, describe } from "bun:test";
import { interprocFindings } from "../src/index";

const run = (code: string, rel = "a.ts") => interprocFindings([{ path: rel, rel, content: code }]);
const has = (code: string, id: string) => run(code).some((f) => f.ruleId === id);

describe("inter-procedural (intra-file) taint via function summaries", () => {
  test("flags tainted input that reaches a sink through a helper", () => {
    expect(has("function q(s){ db.query(s); }\nq(req.body.x);", "VC-SQLI")).toBe(true);
    expect(has("const call = (u) => { fetch(u); };\ncall(req.query.url);", "VC-SSRF")).toBe(true);
    expect(has("function r(c){ exec(c); }\nr(req.query.cmd);", "VC-RCE-CHILD-PROCESS")).toBe(true);
  });
  test("works through a caller-local variable", () => {
    expect(has("function q(s){ db.query(s); }\nconst v = req.body.x;\nq(v);", "VC-SQLI")).toBe(true);
  });
  test("respects a sanitizing reassignment inside the helper", () => {
    expect(run("function q(s){ s = Number(s); db.query(s); }\nq(req.body.x);").length).toBe(0);
  });
  test("does not fire when the call argument is not tainted", () => {
    expect(run("function q(s){ db.query(s); }\nq('SELECT 1');").length).toBe(0);
  });
  test("inter-procedural findings are high confidence", () => {
    expect(run("function q(s){ db.query(s); }\nq(req.body.x);")[0]?.confidence).toBe("high");
  });
  test("taint reaching a sink THROUGH a nested return-tainting helper is detected (Bug 3 regression)", () => {
    // run()'s param flows into exec() only via unwrap()'s return value — the local fixpoint must use returnTainted.
    expect(has("function unwrap(o){ return o.value; }\nfunction run(cmd){ const real = unwrap(cmd); exec(real); }\nrun(req.body);", "VC-RCE-CHILD-PROCESS")).toBe(true);
    // and when the helper's return value is passed straight into the sink call
    expect(has("function pick(o){ return o.q; }\nfunction q(s){ db.query(pick(s)); }\nq(req.body);", "VC-SQLI")).toBe(true);
  });
});
