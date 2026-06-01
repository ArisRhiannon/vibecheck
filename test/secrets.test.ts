import { test, expect, describe } from "bun:test";
import { secretFindings, envFindings, type SourceFile } from "../src/index";

const sf = (rel: string, content: string): SourceFile => ({ path: `/x/${rel}`, rel, content });
const ids = (fs: { ruleId: string }[]) => new Set(fs.map((f) => f.ruleId));

describe("AC2.1/2.2 secrets", () => {
  test("known token formats fire", () => {
    const got = ids(secretFindings([
      sf("a.ts", `const t = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";`),
      sf("b.ts", `const k = "AKIAABCDEFGHIJKLMNOP";`),
      sf("c.ts", `const o = "sk-abcdefghijklmnopqrstuvwx";`),
      sf("d.ts", `const s = "${"x" + "oxb-123456789012-abcdefghijklmnop"}";`),
      sf("key.pem", `-----BEGIN RSA PRIVATE KEY-----\nMIIB...`),
    ]));
    expect(got.has("VC-SECRET-GITHUB")).toBe(true);
    expect(got.has("VC-SECRET-AWS-KEY")).toBe(true);
    expect(got.has("VC-SECRET-OPENAI")).toBe(true);
    expect(got.has("VC-SECRET-SLACK")).toBe(true);
    expect(got.has("VC-SECRET-PRIVATE-KEY")).toBe(true);
  });
  test("high-entropy secret-named assignment fires", () => {
    const f = secretFindings([sf("e.ts", `const dbPassword = "G7x!9qLm2Zr8Vt4Wp1Yk6Hs";`)]);
    expect(ids(f).has("VC-SECRET-HIGH-ENTROPY")).toBe(true);
    expect(f[0]!.line).toBe(1);
  });
  test("safe values do NOT fire (placeholders, env refs, low entropy)", () => {
    const f = secretFindings([
      sf("ok1.ts", `const apiKey = process.env.API_KEY;`),
      sf("ok2.ts", `const token = "your-token-here";`),
      sf("ok3.ts", `const key = "xxxxxxxxxxxxxxxx";`),
      sf("ok4.ts", `const note = "this is a normal sentence value";`),
    ]);
    expect(f.length).toBe(0);
  });
});

describe("AC2.3/2.4 env", () => {
  test("committed .env flagged; example alone is fine", () => {
    expect(ids(envFindings([sf(".env", "API_KEY=real\nDB_URL=postgres://x")])).has("VC-ENV-COMMITTED")).toBe(true);
    expect(ids(envFindings([sf(".env.example", "API_KEY=\n")])).has("VC-ENV-COMMITTED")).toBe(false);
  });
  test("drift between .env and .env.example", () => {
    const f = envFindings([sf(".env", "A=1\nB=2"), sf(".env.example", "A=\nC=")]);
    const got = ids(f);
    expect(got.has("VC-ENV-DRIFT")).toBe(true); // B undocumented
    expect(got.has("VC-ENV-MISSING")).toBe(true); // C missing from .env
  });
  test("drift is paired per-directory, not mispaired across packages (Bug A regression)", () => {
    const f = envFindings([
      sf("pkgA/.env", "A=1"), sf("pkgA/.env.example", "A="),       // matched → no drift
      sf("pkgB/.env", "B=1\nX=2"), sf("pkgB/.env.example", "B="),  // X undocumented in pkgB only
    ]);
    const drift = f.filter((x) => x.ruleId === "VC-ENV-DRIFT");
    expect(drift.length).toBe(1);
    expect(drift[0]!.file).toBe("pkgB/.env.example");
    expect(drift[0]!.message).toContain("X");
    // pkgA matches its own example → no bogus cross-package drift/missing
    expect(f.some((x) => x.ruleId === "VC-ENV-MISSING")).toBe(false);
  });
});
