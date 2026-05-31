import { test, expect, describe } from "bun:test";
import { pythonFindings, pythonAvailable, type SourceFile } from "../src/index";

const run = (code: string, rel = "a.py"): ReturnType<typeof pythonFindings> => pythonFindings([{ path: rel, rel, content: code }]);
const has = (code: string, id: string) => run(code).some((f) => f.ruleId === id);
const d = pythonAvailable() ? describe : describe.skip;

d("Python analyzer (real ast + taint)", () => {
  test("detects Python vuln classes (taint-backed)", () => {
    expect(has("def h():\n    os.system(request.args['c'])", "VC-PY-CMDI")).toBe(true);
    expect(has("def h():\n    subprocess.run(request.args['c'], shell=True)", "VC-PY-CMDI")).toBe(true);
    expect(has(`def h():\n    cursor.execute(f"SELECT {request.args['id']}")`, "VC-PY-SQLI")).toBe(true);
    expect(has("def h():\n    eval(request.form['x'])", "VC-PY-RCE")).toBe(true);
    expect(has("def h():\n    pickle.loads(request.data)", "VC-PY-DESERIALIZE")).toBe(true);
    expect(has("def h():\n    yaml.load(blob)", "VC-PY-YAML")).toBe(true);
  });
  test("safe Python does not fire", () => {
    expect(run(`def h():\n    uid = int(request.args['id'])\n    cursor.execute("SELECT * FROM u WHERE id=%s", [uid])`).length).toBe(0);
    expect(has("def h():\n    subprocess.run(['ls', '-la'])", "VC-PY-CMDI")).toBe(false);
    expect(has("def h():\n    return yaml.safe_load(blob)", "VC-PY-YAML")).toBe(false);
  });
  test("tuple-unpack preserves per-variable taint (QA SEC1)", () => {
    expect(has("def h():\n    a, b = request.args['a'], 'ok'\n    os.system(a)", "VC-PY-CMDI")).toBe(true);
    expect(run("def h():\n    a, b = 'ok', request.args['b']\n    cursor.execute(a)").length).toBe(0);
  });
  test("tainted findings are high confidence", () => {
    expect(run("def h():\n    os.system(request.args['c'])")[0]?.confidence).toBe("high");
  });
});
