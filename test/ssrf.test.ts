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
});
