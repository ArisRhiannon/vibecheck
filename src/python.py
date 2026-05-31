#!/usr/bin/env python3
"""vibecheck Python analyzer: real `ast` parsing + intra-procedural taint. Emits JSON findings.
Usage: python3 python.py <file.py> [<file.py> ...]   ->  stdout JSON array."""
import ast, json, sys

def dotted(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call): return dotted(node.func)
    if isinstance(node, ast.Subscript): return dotted(node.value)
    return None

REQ_ATTRS = {"args", "form", "values", "json", "data", "cookies", "files", "headers", "GET", "POST", "body", "query_params", "params"}
SOURCE_CALLS = {"input", "request.get_json", "request.args.get", "request.form.get", "request.values.get",
                "request.cookies.get", "request.headers.get", "request.json.get", "self.get_argument"}

def is_source(node):
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "request" and node.attr in REQ_ATTRS:
            return True
        d = dotted(node)
        if d and (d == "sys.argv" or d.startswith("request.") and any(f".{a}" in d or d.endswith(a) for a in REQ_ATTRS)):
            return True
        return is_source(node.value) if isinstance(node, ast.Subscript) else (is_source(node.value) if isinstance(node, ast.Attribute) else False)
    if isinstance(node, ast.Call):
        return dotted(node) in SOURCE_CALLS
    return False

NUMERIC = {"int", "float", "bool", "len", "abs"}

def is_tainted(node, tset):
    if node is None: return False
    if isinstance(node, ast.Name): return node.id in tset
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return is_source(node) or is_tainted(node.value, tset)
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, (ast.Add, ast.Mod)) and (is_tainted(node.left, tset) or is_tainted(node.right, tset))
    if isinstance(node, ast.JoinedStr):
        return any(is_tainted(v.value, tset) for v in node.values if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.IfExp):
        return is_tainted(node.body, tset) or is_tainted(node.orelse, tset)
    if isinstance(node, ast.BoolOp):
        return any(is_tainted(v, tset) for v in node.values)
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(is_tainted(e, tset) for e in node.elts)
    if isinstance(node, ast.Call):
        if is_source(node): return True
        d = dotted(node)
        if d in NUMERIC: return False
        if isinstance(node.func, ast.Attribute):
            if is_tainted(node.func.value, tset): return True
            if node.func.attr in ("format", "join") and any(is_tainted(a, tset) for a in node.args): return True
            return False
        if d == "str": return any(is_tainted(a, tset) for a in node.args)
        return False
    return False

def assign_targets(t):
    if isinstance(t, ast.Name): return [t.id]
    if isinstance(t, (ast.Tuple, ast.List)): return [e.id for e in t.elts if isinstance(e, ast.Name)]
    return []

def scope_of(node):
    p = getattr(node, "parent", None)
    while p is not None and not isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        p = getattr(p, "parent", None)
    return p

def taint_sets(tree):
    scopes = {}
    for n in ast.walk(tree):
        recs = []
        if isinstance(n, ast.Assign):
            for tgt in n.targets:
                if isinstance(tgt, (ast.Tuple, ast.List)) and isinstance(n.value, (ast.Tuple, ast.List)) and len(tgt.elts) == len(n.value.elts):
                    for te, ve in zip(tgt.elts, n.value.elts):
                        if isinstance(te, ast.Name): recs.append(([te.id], ve))
                else:
                    nm = assign_targets(tgt)
                    if nm: recs.append((nm, n.value))
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            recs.append(([n.target.id], n.value))
        for names, value in recs:
            scopes.setdefault(id(scope_of(n)), []).append((names, value))
    sets = {}
    for sid, recs in scopes.items():
        s = set()
        for _ in range(6):
            changed = False
            for names, value in recs:
                t = is_tainted(value, s)
                for nm in names:
                    if t and nm not in s: s.add(nm); changed = True
                    elif not t and nm in s: s.discard(nm); changed = True
            if not changed: break
        sets[sid] = s
    return sets

def kw(call, name):
    for k in call.keywords:
        if k.arg == name: return k.value
    return None

def kw_true(call, name):
    v = kw(call, name)
    return isinstance(v, ast.Constant) and v.value is True

def literal(node):
    return isinstance(node, ast.Constant) or (isinstance(node, ast.JoinedStr) and not any(isinstance(v, ast.FormattedValue) for v in node.values))

def fstring_or_concat(node):
    return isinstance(node, ast.JoinedStr) or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))

def analyze(path, src):
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return []
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            c.parent = n
    sets = taint_sets(tree)
    out = []
    def add(node, rule, sev, conf, msg, fix):
        out.append({"ruleId": rule, "severity": sev, "confidence": conf, "file": path,
                    "line": getattr(node, "lineno", 1), "col": getattr(node, "col_offset", 0) + 1,
                    "message": msg, "remediation": fix})
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call): continue
        d = dotted(n.func)
        ts = sets.get(id(scope_of(n)), set())
        a0 = n.args[0] if n.args else None
        T = lambda x: is_tainted(x, ts)
        if d in ("eval", "exec") and a0 is not None and not literal(a0):
            add(n, "VC-PY-RCE", "critical", "high" if T(a0) else "medium", f"{d}() on a non-literal value (remote code execution)", "Never eval/exec dynamic input; use ast.literal_eval or an explicit dispatch.")
        if d in ("os.system", "os.popen") and a0 is not None and not literal(a0):
            add(n, "VC-PY-CMDI", "high", "high" if T(a0) else "medium", f"{d}() with a non-literal command (command injection)", "Use subprocess with a fixed args list and shell=False; validate inputs.")
        if d and d.startswith("subprocess.") and kw_true(n, "shell") and any(T(a) for a in n.args):
            add(n, "VC-PY-CMDI", "high", "high", "subprocess(..., shell=True) with tainted input (command injection)", "Drop shell=True; pass an args list and validate inputs.")
        if d and (d.endswith(".execute") or d.endswith(".executemany") or d.endswith(".raw")) and a0 is not None:
            if T(a0): add(n, "VC-PY-SQLI", "critical", "high", "SQL built from tainted input (SQL injection)", "Use parameterized queries: cursor.execute(sql, params).")
            elif fstring_or_concat(a0): add(n, "VC-PY-SQLI", "medium", "review", "SQL built via f-string/%/+ (verify values are not user-controlled)", "Use parameterized queries with placeholders.")
        if d == "pickle.loads" and T(a0): add(n, "VC-PY-DESERIALIZE", "critical", "high", "pickle.loads() on tainted input (arbitrary code execution)", "Never unpickle untrusted data; use JSON or a safe schema.")
        if d in ("yaml.load",) and kw(n, "Loader") is None and len(n.args) < 2:
            add(n, "VC-PY-YAML", "high", "high", "yaml.load() without a safe Loader (arbitrary object construction)", "Use yaml.safe_load() or Loader=yaml.SafeLoader.")
        if d and d.endswith("render_template_string") and T(a0): add(n, "VC-PY-SSTI", "critical", "high", "render_template_string() with tainted input (server-side template injection)", "Render a fixed template with context variables; never template user input.")
        if d in ("redirect", "flask.redirect") and T(a0): add(n, "VC-PY-OPEN-REDIRECT", "medium", "high", "redirect() to a tainted target (open redirect)", "Redirect only to an allowlist of paths/hosts.")
        if d in ("open", "send_file", "flask.send_file") and T(a0): add(n, "VC-PY-PATH", "high", "high", f"{d}() with a tainted path (path traversal)", "Resolve against a fixed base dir and reject '..' escapes.")
    return out

if __name__ == "__main__":
    try:
        items = json.loads(sys.stdin.read() or "[]")
    except ValueError:
        items = []
    findings = []
    for item in items:
        findings.extend(analyze(item.get("path", ""), item.get("content", "")))
    sys.stdout.write(json.dumps(findings))
