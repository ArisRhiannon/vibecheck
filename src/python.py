#!/usr/bin/env python3
"""vibecheck Python analyzer: real `ast` parsing + inter-procedural taint (return-taint + param->sink,
intra-file and cross-file by resolved import). Reads [{path,content}] on stdin -> JSON findings on stdout."""
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
        return is_source(node.value) if isinstance(node, (ast.Attribute, ast.Subscript)) else False
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

def assign_recs(n):
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
    return recs

def scope_of(node):
    p = getattr(node, "parent", None)
    while p is not None and not isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        p = getattr(p, "parent", None)
    return p

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

def S(rule, sev, conf, msg, fix):
    return {"ruleId": rule, "severity": sev, "confidence": conf, "message": msg, "remediation": fix}

def sinks_for_call(n, T):
    res = []
    d = dotted(n.func)
    a0 = n.args[0] if n.args else None
    if d in ("eval", "exec") and a0 is not None and not literal(a0):
        res.append(S("VC-PY-RCE", "critical", "high" if T(a0) else "medium", f"{d}() on a non-literal value (remote code execution)", "Never eval/exec dynamic input; use ast.literal_eval or an explicit dispatch."))
    if d in ("os.system", "os.popen") and a0 is not None and not literal(a0):
        res.append(S("VC-PY-CMDI", "high", "high" if T(a0) else "medium", f"{d}() with a non-literal command (command injection)", "Use subprocess with a fixed args list and shell=False; validate inputs."))
    if d and d.startswith("subprocess.") and kw_true(n, "shell") and any(T(a) for a in n.args):
        res.append(S("VC-PY-CMDI", "high", "high", "subprocess(..., shell=True) with tainted input (command injection)", "Drop shell=True; pass an args list and validate inputs."))
    if d and (d.endswith(".execute") or d.endswith(".executemany") or d.endswith(".raw")) and a0 is not None:
        if T(a0): res.append(S("VC-PY-SQLI", "critical", "high", "SQL built from tainted input (SQL injection)", "Use parameterized queries: cursor.execute(sql, params)."))
        elif fstring_or_concat(a0): res.append(S("VC-PY-SQLI", "medium", "review", "SQL built via f-string/%/+ (verify values are not user-controlled)", "Use parameterized queries with placeholders."))
    if d == "pickle.loads" and T(a0): res.append(S("VC-PY-DESERIALIZE", "critical", "high", "pickle.loads() on tainted input (arbitrary code execution)", "Never unpickle untrusted data; use JSON or a safe schema."))
    if d in ("yaml.load",) and kw(n, "Loader") is None and len(n.args) < 2:
        res.append(S("VC-PY-YAML", "high", "high", "yaml.load() without a safe Loader (arbitrary object construction)", "Use yaml.safe_load() or Loader=yaml.SafeLoader."))
    if d and d.endswith("render_template_string") and T(a0): res.append(S("VC-PY-SSTI", "critical", "high", "render_template_string() with tainted input (server-side template injection)", "Render a fixed template with context variables; never template user input."))
    if d in ("redirect", "flask.redirect") and T(a0): res.append(S("VC-PY-OPEN-REDIRECT", "medium", "high", "redirect() to a tainted target (open redirect)", "Redirect only to an allowlist of paths/hosts."))
    if d in ("open", "send_file", "flask.send_file") and T(a0): res.append(S("VC-PY-PATH", "high", "high", f"{d}() with a tainted path (path traversal)", "Resolve against a fixed base dir and reject '..' escapes."))
    return res

def params_of(n):
    a = n.args
    return [p.arg for p in (list(getattr(a, "posonlyargs", [])) + list(a.args))]

def set_parents(tree):
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n): c.parent = n

def build_fdata(tree):
    fd, names = {}, {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fd[n.name] = {"params": params_of(n), "assigns": [], "returns": [], "calls": []}
            names[id(n)] = n.name
    for n in ast.walk(tree):
        nm = names.get(id(scope_of(n)))
        if nm is None: continue
        d = fd[nm]
        if isinstance(n, (ast.Assign, ast.AnnAssign)): d["assigns"].extend(assign_recs(n))
        elif isinstance(n, ast.Return): d["returns"].append(n.value)
        elif isinstance(n, ast.Call): d["calls"].append(n)
    return fd

def resolve_module_py(modstr, level, importer, relset):
    parts = modstr.split(".") if modstr else []
    if level and level > 0:
        segs = importer.rsplit("/", 1)[0].split("/") if "/" in importer else []
        segs = [s for s in segs if s]
        up = level - 1
        segs = segs[:len(segs) - up] if up <= len(segs) else []
        cand = "/".join(segs + parts)
    else:
        cand = "/".join(parts)
    for suf in (".py", "/__init__.py"):
        if cand + suf in relset: return cand + suf
    if parts:
        base = parts[-1] + ".py"
        matches = [r for r in relset if r.rsplit("/", 1)[-1] == base]
        if len(matches) == 1: return matches[0]
    return None

def imports_of(tree, modrel, relset):
    named, mods = {}, {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            target = resolve_module_py(n.module, n.level or 0, modrel, relset)
            if target:
                for al in n.names:
                    if al.name != "*": named[al.asname or al.name] = (target, al.name)
        elif isinstance(n, ast.Import):
            for al in n.names:
                target = resolve_module_py(al.name, 0, modrel, relset)
                if target: mods[al.asname or al.name.split(".")[0]] = target
    return named, mods

def make_resolver(modrel, named, mods, localfns):
    def res(callee):
        if isinstance(callee, ast.Name):
            if callee.id in named: return named[callee.id]
            if callee.id in localfns: return (modrel, callee.id)
        elif isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name):
            if callee.value.id in mods: return (mods[callee.value.id], callee.attr)
        return None
    return res

def ret_tainted(node, tset, resolver, summ):
    if node is None: return False
    if isinstance(node, ast.Await): return ret_tainted(node.value, tset, resolver, summ)
    if isinstance(node, ast.Call):
        key = resolver(node.func)
        s = summ.get(key) if key else None
        if not s: return False
        if s["abs"]: return True
        return any(i < len(node.args) and (is_tainted(node.args[i], tset) or ret_tainted(node.args[i], tset, resolver, summ)) for i in s["rparams"])
    return False

def fixpoint(assigns, seed, resolver, summ):
    s = set(seed)
    for _ in range(6):
        ch = False
        for names, value in assigns:
            t = is_tainted(value, s) or ret_tainted(value, s, resolver, summ)
            for nm in names:
                if t and nm not in s: s.add(nm); ch = True
                elif not t and nm in s: s.discard(nm); ch = True
        if not ch: break
    return s

def build_summaries(fdata, resolvers):
    summ = {}
    for _ in range(5):
        changed = False
        for modrel, fns in fdata.items():
            res = resolvers[modrel]
            for fname, fd in fns.items():
                empty = fixpoint(fd["assigns"], set(), res, summ)
                ret_t = lambda s: any(is_tainted(r, s) or ret_tainted(r, s, res, summ) for r in fd["returns"])
                abs0 = ret_t(empty)
                base_high = set()
                Te = lambda x: is_tainted(x, empty) or ret_tainted(x, empty, res, summ)
                for c in fd["calls"]:
                    for s in sinks_for_call(c, Te):
                        if s["confidence"] == "high": base_high.add((id(c), s["ruleId"]))
                rparams, psinks = set(), []
                for i, p in enumerate(fd["params"]):
                    seeded = fixpoint(fd["assigns"], {p}, res, summ)
                    if ret_t(seeded): rparams.add(i)
                    Ts = lambda x, S=seeded: is_tainted(x, S) or ret_tainted(x, S, res, summ)
                    for c in fd["calls"]:
                        for s in sinks_for_call(c, Ts):
                            if s["confidence"] == "high" and (id(c), s["ruleId"]) not in base_high:
                                psinks.append((i, s))
                key = (modrel, fname)
                prev = summ.get(key)
                new = {"abs": abs0, "rparams": rparams, "psinks": psinks}
                if not prev or prev["abs"] != abs0 or len(prev["rparams"]) != len(rparams) or len(prev["psinks"]) != len(psinks):
                    changed = True
                summ[key] = new
        if not changed: break
    return summ

def taint_sets(tree, resolver, summ):
    scopes = {}
    for n in ast.walk(tree):
        for rec in assign_recs(n):
            scopes.setdefault(id(scope_of(n)), []).append(rec)
    sets = {}
    for sid, recs in scopes.items():
        sets[sid] = fixpoint(recs, set(), resolver, summ)
    return sets

def analyze(modrel, tree, summaries, resolver):
    sets = taint_sets(tree, resolver, summaries)
    out, seen = [], set()
    def add(node, s):
        k = (getattr(node, "lineno", 1), s["ruleId"])
        if k in seen: return
        seen.add(k)
        out.append({"ruleId": s["ruleId"], "severity": s["severity"], "confidence": s["confidence"], "file": modrel,
                    "line": getattr(node, "lineno", 1), "col": getattr(node, "col_offset", 0) + 1,
                    "message": s["message"], "remediation": s["remediation"]})
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call): continue
        ts = sets.get(id(scope_of(n)), set())
        T = lambda x: is_tainted(x, ts) or ret_tainted(x, ts, resolver, summaries)
        for s in sinks_for_call(n, T): add(n, s)
        key = resolver(n.func)
        summ = summaries.get(key) if key else None
        if summ:
            for i, sinkinfo in summ["psinks"]:
                if i < len(n.args) and T(n.args[i]): add(n, sinkinfo)
    return out

if __name__ == "__main__":
    try:
        items = json.loads(sys.stdin.read() or "[]")
    except ValueError:
        items = []
    mods = {}
    for it in items:
        try:
            tree = ast.parse(it.get("content", ""))
        except (SyntaxError, ValueError):
            continue
        set_parents(tree)
        mods[it.get("path", "")] = tree
    relset = set(mods)
    fdata, resolvers = {}, {}
    for rel, tree in mods.items():
        fdata[rel] = build_fdata(tree)
        named, modsmap = imports_of(tree, rel, relset)
        resolvers[rel] = make_resolver(rel, named, modsmap, set(fdata[rel].keys()))
    summaries = build_summaries(fdata, resolvers)
    findings = []
    for rel, tree in mods.items():
        findings.extend(analyze(rel, tree, summaries, resolvers[rel]))
    sys.stdout.write(json.dumps(findings))
