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
    expect(run(`package main
func h(r *http.Request){ db.Query("SELECT * FROM u WHERE id = $1", r.FormValue("id")) }`).length).toBe(0);
    expect(has(`package main
func h(){ exec.Command("ls", "-la") }`, "VC-GO-CMDI")).toBe(false);
  });
  test("tainted findings are high confidence", () => {
    expect(run(`package main
func h(r *http.Request){ os.Open(r.FormValue("f")) }`)[0]?.confidence).toBe("high");
  });
  test("inter-procedural: return-taint and param→sink helpers (intra-package)", () => {
    expect(has(`package main
func getInput(r *http.Request) string { return r.FormValue("x") }
func h(r *http.Request){ db.Query(getInput(r)) }`, "VC-GO-SQLI")).toBe(true);
    expect(has(`package main
func run(q string){ db.Query(q) }
func h(r *http.Request){ run(r.FormValue("x")) }`, "VC-GO-SQLI")).toBe(true);
    expect(run(`package main
func run(q string){ db.Query(q) }
func h(){ run("SELECT 1") }`).length).toBe(0);
  });
  test("cross-package resolution (pkg.Func return-taint + param→sink)", () => {
    const sf = (rel: string, content: string) => ({ path: rel, rel, content });
    const ret = [
      sf("util/util.go", `package util
import "net/http"
func GetInput(r *http.Request) string { return r.FormValue("x") }`),
      sf("main.go", `package main
import ("net/http"; "x/util")
func h(r *http.Request){ q := util.GetInput(r); db.Query(q) }`),
    ];
    expect(goFindings(ret).some((f) => f.ruleId === "VC-GO-SQLI" && f.file === "main.go")).toBe(true);
    const ps = [
      sf("store/store.go", `package store
func Run(q string){ database.Query(q) }`),
      sf("main.go", `package main
import ("net/http"; "x/store")
func h(r *http.Request){ store.Run(r.FormValue("x")) }`),
    ];
    expect(goFindings(ps).some((f) => f.ruleId === "VC-GO-SQLI" && f.file === "main.go")).toBe(true);
  });
});
