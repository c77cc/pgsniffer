package pgsql

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fingerprint removes comments and literal values while preserving quoted
// identifiers and PostgreSQL positional parameters. It is deliberately a
// lightweight lexer rather than a SQL parser, so it remains safe on partial or
// extension-specific SQL.
func Fingerprint(query string) string {
	var out strings.Builder
	out.Grow(len(query))
	spacePending := false

	writeSpace := func() {
		if spacePending && out.Len() > 0 {
			out.WriteByte(' ')
		}
		spacePending = false
	}

	for i := 0; i < len(query); {
		c := query[i]

		if isSpace(c) {
			spacePending = true
			i++
			continue
		}
		if c == '-' && i+1 < len(query) && query[i+1] == '-' {
			i += 2
			for i < len(query) && query[i] != '\n' {
				i++
			}
			spacePending = true
			continue
		}
		if c == '/' && i+1 < len(query) && query[i+1] == '*' {
			i += 2
			for i+1 < len(query) && !(query[i] == '*' && query[i+1] == '/') {
				i++
			}
			if i+1 < len(query) {
				i += 2
			}
			spacePending = true
			continue
		}

		writeSpace()
		switch {
		case c == '\'':
			out.WriteByte('?')
			i = skipSingleQuoted(query, i+1)
		case c == '"':
			start := i
			i = skipDoubleQuoted(query, i+1)
			out.WriteString(query[start:i])
		case c == '$':
			if end, ok := dollarQuoteDelimiter(query, i); ok {
				out.WriteByte('?')
				delimiter := query[i:end]
				i = end
				if closeAt := strings.Index(query[i:], delimiter); closeAt >= 0 {
					i += closeAt + len(delimiter)
				}
			} else {
				out.WriteByte(c)
				i++
			}
		case isNumberStart(query, i):
			out.WriteByte('?')
			i = skipNumber(query, i)
		default:
			r, size := utf8.DecodeRuneInString(query[i:])
			out.WriteRune(unicode.ToLower(r))
			i += size
		}
	}

	return strings.TrimSpace(out.String())
}

func skipSingleQuoted(query string, i int) int {
	for i < len(query) {
		if query[i] == '\'' {
			if i+1 < len(query) && query[i+1] == '\'' {
				i += 2
				continue
			}
			return i + 1
		}
		if query[i] == '\\' && i+1 < len(query) {
			i += 2
		} else {
			i++
		}
	}
	return i
}

func skipDoubleQuoted(query string, i int) int {
	for i < len(query) {
		if query[i] == '"' {
			if i+1 < len(query) && query[i+1] == '"' {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return i
}

func dollarQuoteDelimiter(query string, start int) (int, bool) {
	if start+1 >= len(query) || (query[start+1] >= '0' && query[start+1] <= '9') {
		return 0, false
	}
	for i := start + 1; i < len(query); i++ {
		if query[i] == '$' {
			return i + 1, true
		}
		if !(query[i] == '_' || query[i] >= 'a' && query[i] <= 'z' || query[i] >= 'A' && query[i] <= 'Z' || query[i] >= '0' && query[i] <= '9') {
			return 0, false
		}
	}
	return 0, false
}

func isNumberStart(query string, i int) bool {
	if query[i] < '0' || query[i] > '9' {
		return false
	}
	if i == 0 {
		return true
	}
	previous := query[i-1]
	return !isIdentifierByte(previous) && previous != '$'
}

func skipNumber(query string, i int) int {
	for i < len(query) {
		c := query[i]
		if c >= '0' && c <= '9' || c == '.' || c == '_' || c == 'e' || c == 'E' || c == '+' || c == '-' || c == 'x' || c == 'X' {
			i++
			continue
		}
		break
	}
	return i
}

func isIdentifierByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'
}
