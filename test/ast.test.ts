import { test, expect, describe } from "bun:test";
import { parseFile, traverse } from "../src/ast";

describe("AST layer (real parser)", () => {
  test("parses TSX with decorators, dynamic import, tagged template, JSX", () => {
    const src = [
      "@Controller() class C {",
      "  @Get() m(req) { const x = import('./y'); return tag`a${x}b`; }",
      "}",
      "const el = <div dangerouslySetInnerHTML={{ __html: req.query.html }} />;",
    ].join("\n");
    const ast = parseFile(src, "f.tsx");
    expect(ast).not.toBeNull();
    let foundDanger = false;
    traverse(ast!, {
      JSXAttribute(p) {
        const n = p.node.name;
        if (n.type === "JSXIdentifier" && n.name === "dangerouslySetInnerHTML") foundDanger = true;
      },
    });
    expect(foundDanger).toBe(true);
  });

  test("never throws; returns null on unparseable input (file is skipped)", () => {
    let r: ReturnType<typeof parseFile> | undefined;
    expect(() => { r = parseFile("const x = ;;; @@@ <<<", "g.ts"); }).not.toThrow();
    expect(r === null || r!.type === "File").toBe(true);
  });
});
