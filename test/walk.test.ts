import { test, expect, describe } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectFiles } from "../src/walk";

describe("collectFiles language coverage", () => {
  test("includes .py and .go so real scans actually analyze them (regression)", () => {
    const d = mkdtempSync(join(tmpdir(), "vc-walk-"));
    writeFileSync(join(d, "a.py"), "x = 1\n");
    writeFileSync(join(d, "b.go"), "package main\n");
    writeFileSync(join(d, "c.ts"), "const x = 1;\n");
    const rels = collectFiles(d).map((f) => f.rel);
    expect(rels).toContain("a.py");
    expect(rels).toContain("b.go");
    expect(rels).toContain("c.ts");
  });
});
