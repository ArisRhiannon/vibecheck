// vibecheck Go analyzer: real go/parser + go/ast, inter-procedural taint (return-taint + param->sink
// summaries, intra-package by function name). JSON over stdin -> stdout.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strings"
)

type In struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
type Finding struct {
	RuleId, Severity, Confidence, File, Message, Remediation string
	Line, Col                                                int
}

func exprStr(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprStr(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprStr(v.Fun) + "()"
	case *ast.IndexExpr:
		return exprStr(v.X) + "[]"
	case *ast.ParenExpr:
		return exprStr(v.X)
	case *ast.StarExpr:
		return exprStr(v.X)
	}
	return ""
}

func ginRecv(n string) bool { return n == "c" || n == "ctx" || n == "g" || n == "gc" || n == "gctx" }
func ginMethod(n string) bool {
	return n == "Query" || n == "DefaultQuery" || n == "Param" || n == "PostForm" || n == "GetHeader" || n == "Cookie"
}

func isSource(e ast.Expr) bool {
	if ix, ok := e.(*ast.IndexExpr); ok && exprStr(ix.X) == "os.Args" {
		return true
	}
	if exprStr(e) == "os.Args" {
		return true
	}
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	s := exprStr(c.Fun)
	if strings.HasSuffix(s, ".FormValue") || strings.HasSuffix(s, ".PostFormValue") || strings.HasSuffix(s, ".FormFile") || s == "mux.Vars" || strings.HasSuffix(s, ".Header.Get") {
		return true
	}
	if sel, ok2 := c.Fun.(*ast.SelectorExpr); ok2 {
		if sel.Sel.Name == "Get" {
			if inner, ok3 := sel.X.(*ast.CallExpr); ok3 && strings.HasSuffix(exprStr(inner.Fun), ".Query") {
				return true
			}
		}
		if x, ok3 := sel.X.(*ast.Ident); ok3 && ginRecv(x.Name) && ginMethod(sel.Sel.Name) {
			return true
		}
	}
	return false
}

type key struct{ pkg, name string }
type psink struct {
	param int
	hit   Hit
}
type Summary struct {
	abs     bool
	rparams map[int]bool
	psinks  []psink
}
type Hit struct{ rule, sev, msg, fix string }

var summaries map[key]*Summary

func retTainted(e ast.Expr, set map[string]bool, pkg string) bool {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return retTainted(v.X, set, pkg)
	case *ast.CallExpr:
		var k key
		if id, ok := v.Fun.(*ast.Ident); ok {
			k = key{pkg, id.Name}
		} else if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			if x, ok2 := sel.X.(*ast.Ident); ok2 {
				k = key{x.Name, sel.Sel.Name} // cross-package: pkg.Func (selector base == package name)
			} else {
				return false
			}
		} else {
			return false
		}
		s := summaries[k]
		if s == nil {
			return false
		}
		if s.abs {
			return true
		}
		for i := range s.rparams {
			if i < len(v.Args) && (isTainted(v.Args[i], set) || retTainted(v.Args[i], set, pkg)) {
				return true
			}
		}
	}
	return false
}

func isTainted(e ast.Expr, set map[string]bool) bool {
	if e == nil {
		return false
	}
	switch v := e.(type) {
	case *ast.Ident:
		return set[v.Name]
	case *ast.ParenExpr:
		return isTainted(v.X, set)
	case *ast.StarExpr:
		return isTainted(v.X, set)
	case *ast.BinaryExpr:
		return isTainted(v.X, set) || isTainted(v.Y, set)
	case *ast.IndexExpr:
		return isSource(e) || isTainted(v.X, set)
	case *ast.SelectorExpr:
		return isSource(e) || isTainted(v.X, set)
	case *ast.CallExpr:
		if isSource(e) {
			return true
		}
		s := exprStr(v.Fun)
		if s == "strconv.Atoi" || s == "strconv.ParseInt" || s == "strconv.ParseFloat" || s == "strconv.ParseBool" {
			return false
		}
		if s == "fmt.Sprintf" || s == "fmt.Sprint" || s == "fmt.Sprintln" || strings.HasSuffix(s, ".Sprintf") {
			for _, a := range v.Args {
				if isTainted(a, set) {
					return true
				}
			}
			return false
		}
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			return isTainted(sel.X, set)
		}
		return false
	}
	return false
}

var dbRecv = map[string]bool{"db": true, "sql": true, "conn": true, "pool": true, "tx": true, "stmt": true, "database": true, "dbx": true, "sqlx": true}

type rec struct {
	names []string
	rhs   ast.Expr
}

func collectAssigns(body ast.Node) []rec {
	var out []rec
	ast.Inspect(body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
			for i, l := range as.Lhs {
				if id, ok2 := l.(*ast.Ident); ok2 {
					out = append(out, rec{[]string{id.Name}, as.Rhs[i]})
				}
			}
		}
		return true
	})
	return out
}

func collectReturns(body ast.Node) []ast.Expr {
	var out []ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false // do not attribute nested-closure returns to this function
		}
		if r, ok := n.(*ast.ReturnStmt); ok {
			out = append(out, r.Results...)
		}
		return true
	})
	return out
}

func collectCalls(body ast.Node) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			out = append(out, c)
		}
		return true
	})
	return out
}

func computeSet(assigns []rec, seed map[string]bool, pkg string) map[string]bool {
	s := map[string]bool{}
	for k := range seed {
		s[k] = true
	}
	for it := 0; it < 6; it++ {
		ch := false
		for _, r := range assigns {
			t := isTainted(r.rhs, s) || retTainted(r.rhs, s, pkg)
			for _, nm := range r.names {
				if t && !s[nm] {
					s[nm] = true
					ch = true
				} else if !t && s[nm] {
					delete(s, nm)
					ch = true
				}
			}
		}
		if !ch {
			break
		}
	}
	return s
}

func sinkHits(c *ast.CallExpr, T func(ast.Expr) bool) []Hit {
	var hits []Hit
	s := exprStr(c.Fun)
	anyT := func() bool {
		for _, a := range c.Args {
			if T(a) {
				return true
			}
		}
		return false
	}
	if (s == "exec.Command" || s == "exec.CommandContext") && anyT() {
		hits = append(hits, Hit{"VC-GO-CMDI", "high", "exec.Command with tainted input (command injection)", "Pass a fixed program + validated args; never build the command from input."})
	}
	if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
		m := sel.Sel.Name
		if m == "Query" || m == "QueryRow" || m == "Exec" || m == "QueryContext" || m == "QueryRowContext" || m == "ExecContext" {
			qi := 0
			if strings.HasSuffix(m, "Context") {
				qi = 1
			}
			if x, ok3 := sel.X.(*ast.Ident); ok3 && dbRecv[strings.ToLower(x.Name)] && len(c.Args) > qi && T(c.Args[qi]) {
				hits = append(hits, Hit{"VC-GO-SQLI", "critical", "SQL built from tainted input (SQL injection)", "Use parameterized queries with placeholders ($1/?) and args."})
			}
		}
	}
	if (s == "os.Open" || s == "os.ReadFile" || s == "ioutil.ReadFile" || s == "os.OpenFile") && len(c.Args) > 0 && T(c.Args[0]) {
		hits = append(hits, Hit{"VC-GO-PATH", "high", "file path built from tainted input (path traversal)", "Resolve against a fixed base dir and reject '..'."})
	}
	if s == "http.Redirect" && len(c.Args) >= 3 && T(c.Args[2]) {
		hits = append(hits, Hit{"VC-GO-OPEN-REDIRECT", "medium", "redirect target is tainted (open redirect)", "Redirect only to an allowlist of paths/hosts."})
	}
	if (s == "http.Get" || s == "http.Post" || s == "http.Head" || s == "http.NewRequest") && anyT() {
		hits = append(hits, Hit{"VC-GO-SSRF", "high", "outbound request to a tainted URL (SSRF)", "Validate the URL against a host allowlist; block internal IPs."})
	}
	return hits
}

func paramsOf(fn *ast.FuncDecl) []string {
	var ps []string
	if fn.Type.Params == nil {
		return ps
	}
	for _, f := range fn.Type.Params.List {
		if len(f.Names) == 0 {
			ps = append(ps, "")
		}
		for _, n := range f.Names {
			ps = append(ps, n.Name)
		}
	}
	return ps
}

type fnInfo struct {
	pkg, name string
	params    []string
	assigns   []rec
	returns   []ast.Expr
	calls     []*ast.CallExpr
}

func buildSummaries(fns []fnInfo) {
	summaries = map[key]*Summary{}
	for it := 0; it < 5; it++ {
		changed := false
		for _, fn := range fns {
			empty := computeSet(fn.assigns, nil, fn.pkg)
			retT := func(set map[string]bool) bool {
				for _, r := range fn.returns {
					if isTainted(r, set) || retTainted(r, set, fn.pkg) {
						return true
					}
				}
				return false
			}
			base := map[string]bool{}
			for _, c := range fn.calls {
				for _, h := range sinkHits(c, func(e ast.Expr) bool { return isTainted(e, empty) || retTainted(e, empty, fn.pkg) }) {
					base[fmt.Sprintf("%p|%s", c, h.rule)] = true
				}
			}
			abs := retT(empty)
			rparams := map[int]bool{}
			var ps []psink
			for i, p := range fn.params {
				if p == "" {
					continue
				}
				seeded := computeSet(fn.assigns, map[string]bool{p: true}, fn.pkg)
				if retT(seeded) {
					rparams[i] = true
				}
				for _, c := range fn.calls {
					for _, h := range sinkHits(c, func(e ast.Expr) bool { return isTainted(e, seeded) || retTainted(e, seeded, fn.pkg) }) {
						if !base[fmt.Sprintf("%p|%s", c, h.rule)] {
							ps = append(ps, psink{i, h})
						}
					}
				}
			}
			k := key{fn.pkg, fn.name}
			prev := summaries[k]
			ns := &Summary{abs, rparams, ps}
			if prev == nil || prev.abs != abs || len(prev.rparams) != len(rparams) || len(prev.psinks) != len(ps) {
				changed = true
			}
			summaries[k] = ns
		}
		if !changed {
			break
		}
	}
}

func analyze(fset *token.FileSet, file *ast.File, path string, out *[]Finding) {
	pkg := file.Name.Name
	seen := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		set := computeSet(collectAssigns(fn.Body), nil, pkg)
		T := func(e ast.Expr) bool { return isTainted(e, set) || retTainted(e, set, pkg) }
		add := func(c *ast.CallExpr, h Hit) {
			p := fset.Position(c.Pos())
			k := fmt.Sprintf("%d|%s", p.Line, h.rule)
			if seen[k] {
				return
			}
			seen[k] = true
			conf := "high"
			*out = append(*out, Finding{h.rule, h.sev, conf, path, h.msg, h.fix, p.Line, p.Column})
		}
		for _, c := range collectCalls(fn.Body) {
			for _, h := range sinkHits(c, T) {
				add(c, h)
			}
			var sk key
			resolved := false
			if id, ok := c.Fun.(*ast.Ident); ok {
				sk, resolved = key{pkg, id.Name}, true
			} else if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
				if x, ok2 := sel.X.(*ast.Ident); ok2 {
					sk, resolved = key{x.Name, sel.Sel.Name}, true
				}
			}
			if resolved {
				if s := summaries[sk]; s != nil {
					for _, ps := range s.psinks {
						if ps.param < len(c.Args) && T(c.Args[ps.param]) {
							add(c, ps.hit)
						}
					}
				}
			}
		}
	}
}

func main() {
	raw, _ := io.ReadAll(os.Stdin)
	var items []In
	if json.Unmarshal(raw, &items) != nil {
		os.Stdout.WriteString("[]")
		return
	}
	type parsed struct {
		fset *token.FileSet
		file *ast.File
		path string
	}
	var files []parsed
	var fns []fnInfo
	for _, it := range items {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, it.Path, it.Content, 0)
		if err != nil {
			continue
		}
		files = append(files, parsed{fset, f, it.Path})
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				fns = append(fns, fnInfo{f.Name.Name, fn.Name.Name, paramsOf(fn), collectAssigns(fn.Body), collectReturns(fn.Body), collectCalls(fn.Body)})
			}
		}
	}
	buildSummaries(fns)
	out := []Finding{}
	for _, p := range files {
		analyze(p.fset, p.file, p.path, &out)
	}
	b, _ := json.Marshal(out)
	os.Stdout.Write(b)
}
