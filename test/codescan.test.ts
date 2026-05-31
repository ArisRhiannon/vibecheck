import { test, expect, describe } from "bun:test";
import { codeFindings, type SourceFile } from "../src/index";

const sf = (content: string, rel = "a.ts"): SourceFile => ({ path: `/x/${rel}`, rel, content });
const has = (c: string, id: string) => codeFindings([sf(c)]).some((f) => f.ruleId === id);

describe("AC3.1 RCE", () => {
  test("non-literal eval / child_process fire; literals do not", () => {
    expect(has("eval(userInput)", "VC-RCE-EVAL")).toBe(true);
    expect(has("eval(`${x}`)", "VC-RCE-EVAL")).toBe(true);
    expect(has('eval("2 + 2")', "VC-RCE-EVAL")).toBe(false);
    expect(has("execSync(cmd)", "VC-RCE-CHILD-PROCESS")).toBe(true);
    expect(has('execSync("git " + branch)', "VC-RCE-CHILD-PROCESS")).toBe(true);
    expect(has('execSync("ls -la")', "VC-RCE-CHILD-PROCESS")).toBe(false);
  });
});

describe("AC3.2 SQL injection", () => {
  test("interpolation/concat fire; parameterized does not", () => {
    expect(has("db.query(`SELECT * FROM users WHERE id = ${id}`)", "VC-SQLI-TEMPLATE")).toBe(true);
    expect(has('const q = "DELETE FROM t WHERE x=" + y', "VC-SQLI-CONCAT")).toBe(true);
    expect(has('db.query("SELECT * FROM users WHERE id = $1", [id])', "VC-SQLI-TEMPLATE")).toBe(false);
    expect(has('db.query("SELECT * FROM users WHERE id = $1", [id])', "VC-SQLI-CONCAT")).toBe(false);
  });
});

describe("AC3.3 CORS", () => {
  test("wildcard fires (high with credentials); locked-down does not", () => {
    const f = codeFindings([sf('app.use(cors({ origin: "*", credentials: true }))')]);
    const w = f.find((x) => x.ruleId === "VC-CORS-WILDCARD");
    expect(w?.severity).toBe("high");
    expect(has('cors({ origin: "https://app.example.com" })', "VC-CORS-WILDCARD")).toBe(false);
  });
});

describe("AC3.4 JWT", () => {
  test("none + unpinned fire; pinned does not", () => {
    expect(has('jwt.verify(token, secret, { algorithms: ["none"] })', "VC-JWT-NONE")).toBe(true);
    expect(has("jwt.verify(token, secret)", "VC-JWT-UNPINNED")).toBe(true);
    expect(has('jwt.verify(token, secret, { algorithms: ["HS256"] })', "VC-JWT-UNPINNED")).toBe(false);
  });
});

describe("AC3.5 cookies", () => {
  test("auth cookie without httpOnly+secure fires; hardened does not", () => {
    expect(has('res.cookie("session", t, { httpOnly: true })', "VC-COOKIE-INSECURE")).toBe(true);
    expect(has('res.cookie("session", t, { httpOnly: true, secure: true })', "VC-COOKIE-INSECURE")).toBe(false);
    expect(has('res.cookie("theme", "dark")', "VC-COOKIE-INSECURE")).toBe(false);
  });
});
