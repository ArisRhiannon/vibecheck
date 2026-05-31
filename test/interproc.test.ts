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
});
