import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { collectFiles, locate, lineAt, VibecheckError } from "../src/index";

const tmp = mkdtempSync(join(tmpdir(), "vibecheck-walk-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const mk = (rel: string, content: string) => {
  const f = join(tmp, rel);
  mkdirSync(dirname(f), { recursive: true });
  writeFileSync(f, content);
};

mk(".gitignore", "*.log\nsecret/\n/build\n");
mk("src/a.ts", "const x = 1;\nconst y = 2;\n");
mk("node_modules/dep/index.js", "module.exports = 1;");
mk("app.log", "noise");
mk("secret/s.ts", "const k = 'x';");
mk("build/out.js", "compiled");
mk("weird.js", "var a=1;\u0000\u0000binary");
mk("huge.js", "a".repeat(1_600_000));

describe("AC1.1/1.4 walk", () => {
  const rels = collectFiles(tmp).map((f) => f.rel);
  test("includes real source, excludes build/gitignored/binary/huge", () => {
    expect(rels).toContain("src/a.ts");
    expect(rels).not.toContain("node_modules/dep/index.js");
    expect(rels).not.toContain("app.log"); // *.log
    expect(rels).not.toContain("secret/s.ts"); // ignored dir
    expect(rels).not.toContain("build/out.js"); // /build
    expect(rels).not.toContain("weird.js"); // binary (NUL)
    expect(rels).not.toContain("huge.js"); // > size cap
  });
  test("missing directory throws VibecheckError", () => {
    expect(() => collectFiles(join(tmp, "nope"))).toThrow(VibecheckError);
  });
});

describe("AC1.2 locate / lineAt", () => {
  test("1-based line/col", () => {
    const c = "ab\ncde\nf";
    expect(locate(c, 0)).toEqual({ line: 1, col: 1 });
    expect(locate(c, 3)).toEqual({ line: 2, col: 1 }); // 'c'
    expect(locate(c, 5)).toEqual({ line: 2, col: 3 }); // 'e'
    expect(lineAt(c, 4)).toBe("cde");
  });
});
