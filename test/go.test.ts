import { test, expect, describe } from "bun:test";
import { goFindings, goAvailable } from "../src/index";

const run = (code: string, rel = "a.go") => goFindings([{ path: rel, rel, content: code }]);
const has = (code: string, id: string) => run(code).some((f) => f.ruleId === id);
const d = goAvailable() ? describe : describe.skip;

d("Go analyzer (real go/parser + taint)", () => {
  test("detects Go vuln classes (taint-backed)", () => {
    expect(has(`package main
func h(r *http.Request){ exec.Command("sh", "-c", r.FormValue("c")) }`, "VC-GO-CMDI")).toBe(true);
    expect(has(`package main
func h(r *http.Request){ q := r.FormValue("id"); db.Query("SELECT " + q) }`, "VC-GO-SQLI")).toBe(true);
    expect(has(`package main
func h(r *http.Request){ os.Open(r.FormValue("f")) }`, "VC-GO-PATH")).toBe(true);
    expect(has(`package main
func h(r *http.Request){ http.Get(r.FormValue("u")) }`, "VC-GO-SSRF")).toBe(true);
  });
  test("safe Go does not fire", () => {
    expect(run(`package main
func h(r *http.Request){ id, _ := strconv.Atoi(r.FormValue("id")); db.Query("SELECT * WHERE id=$1", id) }`).length).toBe(0);
    expect(has(`package main
func h(){ exec.Command("ls", "-la") }`, "VC-GO-CMDI")).toBe(false);
  });
  test("tainted findings are high confidence", () => {
    expect(run(`package main
func h(r *http.Request){ os.Open(r.FormValue("f")) }`)[0]?.confidence).toBe("high");
  });
});
