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
	var root ast.Node
	if file != nil {
		root = file
	}
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

// pythonCode masks comments and single/triple quoted literals without changing
// byte positions. It records f-string starts separately from literal contents.
// This is bounded lexical screening, not Python parsing or dataflow analysis.
func pythonCode(content string) (string, []int) {
	code := []byte(content)
	var formatted []int
	blank := func(start, end int) {
		for i := start; i < end; i++ {
			if code[i] != '\n' && code[i] != '\r' {
				code[i] = ' '
			}
		}
	}
	identifier := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
	}
	for i := 0; i < len(content); {
		if content[i] == '#' {
			end := i
			for end < len(content) && content[end] != '\n' {
				end++
			}
			blank(i, end)
			i = end
			continue
		}
		if content[i] != '\'' && content[i] != '"' {
			i++
			continue
		}
		start, quote, width := i, content[i], 1
		prefixStart := i
		for prefixStart > 0 && identifier(content[prefixStart-1]) {
			prefixStart--
		}
		prefix := strings.ToLower(content[prefixStart:i])
		if prefix == "f" || prefix == "fr" || prefix == "rf" {
			formatted = append(formatted, i)
		}
		if i+2 < len(content) && content[i+1] == quote && content[i+2] == quote {
			width = 3
		}
		i += width
		for i < len(content) {
			if content[i] == '\\' {
				i += 2
				continue
			}
			if content[i] == quote && (width == 1 || i+2 < len(content) && content[i+1] == quote && content[i+2] == quote) {
				i += width
				break
			}
			i++
		}
		if i > len(content) {
			i = len(content)
		}
		blank(start, i)
	}
	return string(code), formatted
}

func pythonShellInterpolation(content string) map[int]bool {
	lines := map[int]bool{}
	code, fstrings := pythonCode(content)
	for _, loc := range pythonCall.FindAllStringIndex(code, -1) {
		start, depth, end := loc[1], 1, loc[1]
		for ; end < len(code) && end-start < 1<<20; end++ {
			if code[end] == '(' {
				depth++
			}
			if code[end] == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		if depth != 0 {
			continue
		}
		body := content[start:end]
		shell := pythonShellFlag.MatchString(code[start:end]) || pythonShellList.MatchString(body)
		formatted := strings.ContainsAny(code[start:end], "+%")
		for _, pos := range fstrings {
			if pos >= start && pos < end {
				formatted = true
				break
			}
		}
		if shell && formatted {
			lines[strings.Count(content[:loc[0]], "\n")+1] = true
		}
	}
	return lines
}
