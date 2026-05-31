// vibecheck Go analyzer: real go/parser + go/ast, intra-procedural taint. JSON over stdin -> stdout.
package main

import (
	"encoding/json"
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
	if ix, ok := e.(*ast.IndexExpr); ok {
		if exprStr(ix.X) == "os.Args" {
			return true
		}
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
		if sel.Sel.Name == "Get" { // r.URL.Query().Get(...)
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

func taintSet(body *ast.BlockStmt) map[string]bool {
	type rec struct {
		name string
		rhs  ast.Expr
	}
	var recs []rec
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if ok && len(as.Lhs) == len(as.Rhs) {
			for i, l := range as.Lhs {
				if id, ok2 := l.(*ast.Ident); ok2 {
					recs = append(recs, rec{id.Name, as.Rhs[i]})
				}
			}
		}
		return true
	})
	set := map[string]bool{}
	for k := 0; k < 6; k++ {
		changed := false
		for _, r := range recs {
			t := isTainted(r.rhs, set)
			if t && !set[r.name] {
				set[r.name] = true
				changed = true
			} else if !t && set[r.name] {
				delete(set, r.name)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return set
}

func anyTainted(args []ast.Expr, set map[string]bool) bool {
	for _, a := range args {
		if isTainted(a, set) {
			return true
		}
	}
	return false
}

func analyze(fset *token.FileSet, file *ast.File, path string, out *[]Finding) {
	add := func(n ast.Node, rule, sev, msg, fix string) {
		p := fset.Position(n.Pos())
		*out = append(*out, Finding{rule, sev, "high", path, msg, fix, p.Line, p.Column})
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		set := taintSet(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			s := exprStr(c.Fun)
			if (s == "exec.Command" || s == "exec.CommandContext") && anyTainted(c.Args, set) {
				add(c, "VC-GO-CMDI", "high", "exec.Command with tainted input (command injection)", "Pass a fixed program + validated args; never build the command from input.")
			}
			if sel, ok2 := c.Fun.(*ast.SelectorExpr); ok2 {
				m := sel.Sel.Name
				if m == "Query" || m == "QueryRow" || m == "Exec" || m == "QueryContext" || m == "QueryRowContext" || m == "ExecContext" {
					qi := 0
					if strings.HasSuffix(m, "Context") {
						qi = 1
					}
					if x, ok3 := sel.X.(*ast.Ident); ok3 && dbRecv[strings.ToLower(x.Name)] && len(c.Args) > qi && isTainted(c.Args[qi], set) {
						add(c, "VC-GO-SQLI", "critical", "SQL built from tainted input (SQL injection)", "Use parameterized queries with placeholders ($1/?) and args.")
					}
				}
			}
			if (s == "os.Open" || s == "os.ReadFile" || s == "ioutil.ReadFile" || s == "os.OpenFile") && len(c.Args) > 0 && isTainted(c.Args[0], set) {
				add(c, "VC-GO-PATH", "high", "file path built from tainted input (path traversal)", "Resolve against a fixed base dir and reject '..'.")
			}
			if s == "http.Redirect" && len(c.Args) >= 3 && isTainted(c.Args[2], set) {
				add(c, "VC-GO-OPEN-REDIRECT", "medium", "redirect target is tainted (open redirect)", "Redirect only to an allowlist of paths/hosts.")
			}
			if (s == "http.Get" || s == "http.Post" || s == "http.Head" || s == "http.NewRequest") && anyTainted(c.Args, set) {
				add(c, "VC-GO-SSRF", "high", "outbound request to a tainted URL (SSRF)", "Validate the URL against a host allowlist; block internal IPs.")
			}
			return true
		})
	}
}

func main() {
	raw, _ := io.ReadAll(os.Stdin)
	var items []In
	if json.Unmarshal(raw, &items) != nil {
		os.Stdout.WriteString("[]")
		return
	}
	out := []Finding{}
	for _, it := range items {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, it.Path, it.Content, 0)
		if err != nil {
			continue
		}
		analyze(fset, f, it.Path, &out)
	}
	b, _ := json.Marshal(out)
	os.Stdout.Write(b)
}
