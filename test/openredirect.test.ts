import { test, expect, describe } from "bun:test";
import { astFindings } from "../src/index";

const run = (code: string, rel = "a.ts") => astFindings([{ path: rel, rel, content: code }]);
const has = (code: string, id: string) => run(code).some((f) => f.ruleId === id);

describe("open-redirect: relative vs host-controlled (corpus-driven)", () => {
  test("a fixed-prefix relative redirect is NOT flagged", () => {
    expect(has("res.redirect('/user/' + req.params.id);", "VC-OPEN-REDIRECT")).toBe(false);
    expect(has("res.redirect(`/dashboard/${req.query.tab}`);", "VC-OPEN-REDIRECT")).toBe(false);
  });
  test("a fully attacker-controlled redirect target IS flagged", () => {
    expect(has("res.redirect(req.query.url);", "VC-OPEN-REDIRECT")).toBe(true);
  });
});
