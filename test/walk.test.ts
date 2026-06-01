import { test, expect, describe } from "bun:test";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
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

describe("collectFiles honors .gitignore semantics", () => {
  test("negation (!) re-includes a file git would track (Bug B regression)", () => {
    const d = mkdtempSync(join(tmpdir(), "vc-gi-"));
    writeFileSync(join(d, ".gitignore"), "config/*.json\n!config/keep.json\n");
    mkdirSync(join(d, "config"), { recursive: true });
    writeFileSync(join(d, "config", "drop.json"), "{}");
    writeFileSync(join(d, "config", "keep.json"), "{}");
    const rels = collectFiles(d).map((f) => f.rel);
    expect(rels).toContain("config/keep.json"); // un-ignored via !
    expect(rels).not.toContain("config/drop.json"); // still ignored
  });
  test("** matches across path separators incl. zero dirs (Bug C regression)", () => {
    const d = mkdtempSync(join(tmpdir(), "vc-gi-"));
    writeFileSync(join(d, ".gitignore"), "assets/**/*.txt\n");
    mkdirSync(join(d, "assets", "a", "b"), { recursive: true });
    writeFileSync(join(d, "assets", "shallow.txt"), "x"); // assets/shallow.txt (zero intermediate dirs)
    writeFileSync(join(d, "assets", "a", "b", "deep.txt"), "x"); // assets/a/b/deep.txt
    writeFileSync(join(d, "keep.txt"), "x");
    const rels = collectFiles(d).map((f) => f.rel);
    expect(rels).not.toContain("assets/shallow.txt");
    expect(rels).not.toContain("assets/a/b/deep.txt");
    expect(rels).toContain("keep.txt");
  });
});
