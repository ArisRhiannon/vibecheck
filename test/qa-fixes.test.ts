import { test, expect, describe } from "bun:test";
import { codeFindings, routeFindings, type SourceFile } from "../src/index";

const sf = (content: string, rel = "a.ts"): SourceFile => ({ path: `/x/${rel}`, rel, content });
const hasCode = (c: string, id: string) => codeFindings([sf(c)]).some((f) => f.ruleId === id);
const hasRoute = (c: string, id: string) => routeFindings([sf(c)]).some((f) => f.ruleId === id);

describe("QA: child_process FP fix (DET3)", () => {
  test("ORM/RegExp .exec() do NOT fire; real child_process does", () => {
    expect(hasCode("const u = await User.find().exec();", "VC-RCE-CHILD-PROCESS")).toBe(false);
    expect(hasCode("const m = /ab+c/.exec(input);", "VC-RCE-CHILD-PROCESS")).toBe(false);
    expect(hasCode("exec(cmd);", "VC-RCE-CHILD-PROCESS")).toBe(true);
    expect(hasCode("child_process.exec(userCmd);", "VC-RCE-CHILD-PROCESS")).toBe(true);
    expect(hasCode('exec("ls -la");', "VC-RCE-CHILD-PROCESS")).toBe(false);
  });
});

describe("QA: service_role comment FP fix (DET5)", () => {
  test("comment mention does NOT fire; real reference does", () => {
    expect(hasRoute("// remember to set the service_role key in env", "VC-SUPABASE-SERVICE-ROLE")).toBe(false);
    expect(hasRoute("const k = process.env.SUPABASE_SERVICE_ROLE_KEY;", "VC-SUPABASE-SERVICE-ROLE")).toBe(true);
  });
});
