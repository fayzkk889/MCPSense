package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func goShellInterpolation(content string) map[int]bool {
	lines := map[int]bool{}
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, "input.go", content, parser.AllErrors)
	var root ast.Node = file
	if expr, err := parser.ParseExprFrom(fset, "expression.go", content, 0); err == nil {
		root = expr
	}
	if root == nil {
		return lines
	}
	ast.Inspect(root, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "exec" {
			return true
		}
		index := 0
		if sel.Sel.Name == "CommandContext" {
			index = 1
		} else if sel.Sel.Name != "Command" {
			return true
		}
		if len(call.Args) <= index {
			return true
		}
		literal, ok := call.Args[index].(*ast.BasicLit)
		if !ok {
			return true
		}
		command, err := strconv.Unquote(literal.Value)
		if err != nil {
			return true
		}
		name := strings.ToLower(filepath.Base(strings.ReplaceAll(command, "\\", "/")))
		name = strings.TrimSuffix(name, ".exe")
		shell := false
		for _, arg := range call.Args[index+1:] {
			if flag, ok := arg.(*ast.BasicLit); ok {
				value, err := strconv.Unquote(flag.Value)
				if err != nil {
					continue
				}
				value = strings.ToLower(value)
				switch name {
				case "sh", "bash", "zsh", "dash", "ksh", "fish":
					shell = shell || (strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(value, "c"))
				case "cmd":
					shell = shell || value == "/c" || value == "/k"
				case "powershell", "pwsh":
					shell = shell || value == "-c" || value == "-command"
				}
			}
		}
		if !shell {
			return true
		}
		formatted := false
		for _, arg := range call.Args[index+1:] {
			ast.Inspect(arg, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.BinaryExpr:
					formatted = formatted || v.Op == token.ADD
				case *ast.CallExpr:
					if s, ok := v.Fun.(*ast.SelectorExpr); ok {
						if p, ok := s.X.(*ast.Ident); ok && p.Name == "fmt" && s.Sel.Name == "Sprintf" {
							formatted = true
						}
					}
				}
				return true
			})
		}
		if formatted {
			lines[fset.Position(call.Pos()).Line] = true
		}
		return true
	})
	return lines
}

var pythonCall = regexp.MustCompile(`\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(`)
var pythonShellFlag = regexp.MustCompile(`\bshell\s*=\s*True\b`)
var pythonShellList = regexp.MustCompile(`(?s)^\s*\[\s*["'](?:/bin/)?(?:sh|bash|dash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']\s*,\s*["'](?:-[a-z]*c|/c|-Command)["']`)
var pythonFString = regexp.MustCompile(`\b[fF][rR]?["']`)

// Bound each lexical call by balanced parentheses, ignoring parentheses in
// quoted strings. This is not Python dataflow or complete language analysis.
func pythonShellInterpolation(content string) map[int]bool {
	lines := map[int]bool{}
	for _, loc := range pythonCall.FindAllStringIndex(content, -1) {
		start := loc[1]
		depth := 1
		quote := byte(0)
		escaped := false
		end := start
		var code strings.Builder
		for ; end < len(content) && end-start < 1<<20; end++ {
			c := content[end]
			if quote != 0 {
				code.WriteByte(' ')
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
				} else if c == quote {
					quote = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				quote = c
				code.WriteByte(' ')
				continue
			}
			if c == '(' {
				depth++
			}
			if c == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
			code.WriteByte(c)
		}
		if depth != 0 {
			continue
		}
		body := content[start:end]
		shell := pythonShellFlag.MatchString(code.String()) || pythonShellList.MatchString(body)
		formatted := pythonFString.MatchString(body) || strings.ContainsAny(code.String(), "+%")
		if shell && formatted {
			lines[strings.Count(content[:loc[0]], "\n")+1] = true
		}
	}
	return lines
}
