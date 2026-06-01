import { test, expect, describe } from "bun:test";
import { astFindings } from "../src/index";

const has = (code: string, id: string, rel = "a.ts") => astFindings([{ path: rel, rel, content: code }]).some((f) => f.ruleId === id);

describe("SSRF requires a server source, not client-side DOM location (corpus-driven)", () => {
  test("client-side document.location / location fetch is NOT SSRF", () => {
    expect(has("fetch(`${document.location}?x=1`);", "VC-SSRF")).toBe(false);
    expect(has("fetch(location.href);", "VC-SSRF")).toBe(false);
  });
  test("a server-controlled URL IS SSRF (direct and via variable)", () => {
    expect(has("fetch(req.query.url);", "VC-SSRF")).toBe(true);
    expect(has("const u = req.query.url;\nfetch(u);", "VC-SSRF")).toBe(true);
  });
  test("a DOM-location URL via an intermediate variable is NOT SSRF (validation FP)", () => {
    expect(has("const host = document.location.hostname;\nfetch('https://' + host + '/api');", "VC-SSRF")).toBe(false);
    expect(has("const base = window.location.origin;\nfetch(base + '/api');", "VC-SSRF")).toBe(false);
  });
  test("a server-tainted var REASSIGNED to a client-side location is NOT SSRF (Bug 2 regression)", () => {
    // server-taint must clear on the clean/client reassignment (serverTaintSets symmetric with buildTaintSets)
    expect(has("let u = req.body.url;\nu = document.location.href;\nfetch(u);", "VC-SSRF")).toBe(false);
  });
});
