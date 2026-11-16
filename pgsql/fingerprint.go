package pgsql

import (
	"strings"
	"unicode/utf8"
)

type fingerprintTokenKind uint8

const (
	tokenWord fingerprintTokenKind = iota
	tokenQuotedIdentifier
	tokenLiteral
	tokenParameter
	tokenPunctuation
	tokenOperator
	tokenMarker
)

type fingerprintToken struct {
	kind fingerprintTokenKind
	text string
}

// Fingerprint removes comments and literal values and canonicalizes formatting
// while preserving quoted identifiers and PostgreSQL positional parameters. It
// intentionally remains a lexer, so partial and extension-specific SQL is safe.
func Fingerprint(query string) string {
	tokens := lexFingerprint(query)
	tokens = collapseLiteralLists(tokens)
	tokens = collapseRepeatedValues(tokens)
	for len(tokens) > 0 && tokens[len(tokens)-1].text == ";" {
		tokens = tokens[:len(tokens)-1]
	}
	return renderFingerprint(tokens)
}

func lexFingerprint(query string) []fingerprintToken {
	tokens := make([]fingerprintToken, 0, len(query)/3)
	for i := 0; i < len(query); {
		if isSpace(query[i]) {
			i++
			continue
		}
		if query[i] == '-' && i+1 < len(query) && query[i+1] == '-' {
			i = skipLineComment(query, i+2)
			continue
		}
		if query[i] == '/' && i+1 < len(query) && query[i+1] == '*' {
			i = skipBlockComment(query, i+2)
			continue
		}
		if end, ok := prefixedStringEnd(query, i); ok {
			tokens = append(tokens, fingerprintToken{kind: tokenLiteral, text: "?"})
			i = end
			continue
		}
		if end, ok := prefixedIdentifierEnd(query, i); ok {
			tokens = append(tokens, fingerprintToken{kind: tokenQuotedIdentifier, text: "u&" + query[i+2:end]})
			i = end
			continue
		}

		switch query[i] {
		case '\'':
			tokens = append(tokens, fingerprintToken{kind: tokenLiteral, text: "?"})
			i = skipSingleQuoted(query, i+1, false)
			continue
		case '"':
			start := i
			i = skipDoubleQuoted(query, i+1)
			tokens = append(tokens, fingerprintToken{kind: tokenQuotedIdentifier, text: query[start:i]})
			continue
		case '$':
			if end, ok := dollarQuoteDelimiter(query, i); ok {
				delimiter := query[i:end]
				i = end
				if closeAt := strings.Index(query[i:], delimiter); closeAt >= 0 {
					i += closeAt + len(delimiter)
				} else {
					i = len(query)
				}
				tokens = append(tokens, fingerprintToken{kind: tokenLiteral, text: "?"})
				continue
			}
			if end := positionalParameterEnd(query, i); end > i {
				tokens = append(tokens, fingerprintToken{kind: tokenParameter, text: query[i:end]})
				i = end
				continue
			}
		}

		if isNumberStart(query, i) {
			tokens = append(tokens, fingerprintToken{kind: tokenLiteral, text: "?"})
			i = skipNumber(query, i)
			continue
		}
		if isPunctuation(query[i]) {
			tokens = append(tokens, fingerprintToken{kind: tokenPunctuation, text: query[i : i+1]})
			i++
			continue
		}
		if isOperator(query[i]) {
			start := i
			for i < len(query) && isOperator(query[i]) && !startsComment(query, i) {
				i++
			}
			tokens = append(tokens, fingerprintToken{kind: tokenOperator, text: query[start:i]})
			continue
		}

		start := i
		for i < len(query) && !isTokenBoundary(query, i) {
			_, size := utf8.DecodeRuneInString(query[i:])
			i += size
		}
		if start == i {
			_, size := utf8.DecodeRuneInString(query[i:])
			i += size
		}
		word := strings.ToLower(query[start:i])
		if isLiteralKeyword(word) {
			tokens = append(tokens, fingerprintToken{kind: tokenLiteral, text: "?"})
		} else {
			tokens = append(tokens, fingerprintToken{kind: tokenWord, text: word})
		}
	}
	return tokens
}

func skipLineComment(query string, i int) int {
	for i < len(query) && query[i] != '\n' {
		i++
	}
	return i
}

func skipBlockComment(query string, i int) int {
	depth := 1
	for i < len(query) && depth > 0 {
		switch {
		case i+1 < len(query) && query[i] == '/' && query[i+1] == '*':
			depth++
			i += 2
		case i+1 < len(query) && query[i] == '*' && query[i+1] == '/':
			depth--
			i += 2
		default:
			i++
		}
	}
	return i
}

func prefixedStringEnd(query string, i int) (int, bool) {
	if i+1 < len(query) && (query[i] == 'e' || query[i] == 'E' || query[i] == 'b' || query[i] == 'B' || query[i] == 'x' || query[i] == 'X' || query[i] == 'n' || query[i] == 'N') && query[i+1] == '\'' {
		return skipSingleQuoted(query, i+2, query[i] == 'e' || query[i] == 'E'), true
	}
	if i+2 < len(query) && (query[i] == 'u' || query[i] == 'U') && query[i+1] == '&' && query[i+2] == '\'' {
		return skipSingleQuoted(query, i+3, false), true
	}
	return 0, false
}

func prefixedIdentifierEnd(query string, i int) (int, bool) {
	if i+2 < len(query) && (query[i] == 'u' || query[i] == 'U') && query[i+1] == '&' && query[i+2] == '"' {
		return skipDoubleQuoted(query, i+3), true
	}
	return 0, false
}

func skipSingleQuoted(query string, i int, backslashEscapes bool) int {
	for i < len(query) {
		if query[i] == '\'' {
			if i+1 < len(query) && query[i+1] == '\'' {
				i += 2
				continue
			}
			return i + 1
		}
		if backslashEscapes && query[i] == '\\' && i+1 < len(query) {
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
	if start+1 >= len(query) || query[start+1] >= '0' && query[start+1] <= '9' {
		return 0, false
	}
	for i := start + 1; i < len(query); i++ {
		if query[i] == '$' {
			return i + 1, true
		}
		if !isIdentifierByte(query[i]) {
			return 0, false
		}
	}
	return 0, false
}

func positionalParameterEnd(query string, start int) int {
	i := start + 1
	for i < len(query) && query[i] >= '0' && query[i] <= '9' {
		i++
	}
	if i == start+1 {
		return start
	}
	return i
}

func isNumberStart(query string, i int) bool {
	if query[i] >= '0' && query[i] <= '9' {
		return i == 0 || !isIdentifierByte(query[i-1]) && query[i-1] != '$'
	}
	return query[i] == '.' && i+1 < len(query) && query[i+1] >= '0' && query[i+1] <= '9'
}

func skipNumber(query string, i int) int {
	if i+1 < len(query) && query[i] == '0' && (query[i+1] == 'x' || query[i+1] == 'X' || query[i+1] == 'b' || query[i+1] == 'B' || query[i+1] == 'o' || query[i+1] == 'O') {
		i += 2
		for i < len(query) && (isHexDigit(query[i]) || query[i] == '_') {
			i++
		}
		return i
	}
	seenDot := false
	if query[i] == '.' {
		seenDot = true
		i++
	}
	for i < len(query) && (query[i] >= '0' && query[i] <= '9' || query[i] == '_') {
		i++
	}
	if !seenDot && i < len(query) && query[i] == '.' && (i+1 >= len(query) || query[i+1] != '.') {
		i++
		for i < len(query) && (query[i] >= '0' && query[i] <= '9' || query[i] == '_') {
			i++
		}
	}
	if i < len(query) && (query[i] == 'e' || query[i] == 'E') {
		exponent := i
		i++
		if i < len(query) && (query[i] == '+' || query[i] == '-') {
			i++
		}
		digits := i
		for i < len(query) && (query[i] >= '0' && query[i] <= '9' || query[i] == '_') {
			i++
		}
		if i == digits {
			i = exponent
		}
	}
	return i
}

func collapseLiteralLists(tokens []fingerprintToken) []fingerprintToken {
	result := make([]fingerprintToken, 0, len(tokens))
	for i := 0; i < len(tokens); {
		if tokens[i].kind == tokenWord && (tokens[i].text == "in" || tokens[i].text == "array") && i+2 < len(tokens) {
			open, close := "(", ")"
			if tokens[i].text == "array" {
				open, close = "[", "]"
			}
			if tokens[i+1].text == open {
				if end, ok := literalListEnd(tokens, i+2, close); ok {
					result = append(result, tokens[i], tokens[i+1], fingerprintToken{kind: tokenLiteral, text: "?"}, tokens[end])
					i = end + 1
					continue
				}
			}
		}
		result = append(result, tokens[i])
		i++
	}
	return result
}

func literalListEnd(tokens []fingerprintToken, start int, close string) (int, bool) {
	expectValue := true
	values := 0
	for i := start; i < len(tokens); i++ {
		if tokens[i].text == close {
			return i, values > 0 && !expectValue
		}
		if expectValue {
			if tokens[i].kind != tokenLiteral && tokens[i].kind != tokenParameter {
				return 0, false
			}
			values++
			expectValue = false
		} else {
			if tokens[i].text != "," {
				return 0, false
			}
			expectValue = true
		}
	}
	return 0, false
}

func collapseRepeatedValues(tokens []fingerprintToken) []fingerprintToken {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].kind != tokenWord || tokens[i].text != "values" || i+1 >= len(tokens) || tokens[i+1].text != "(" {
			continue
		}
		firstEnd := matchingDelimiter(tokens, i+1, "(", ")")
		if firstEnd < 0 {
			continue
		}
		end := firstEnd
		groups := 1
		for end+2 < len(tokens) && tokens[end+1].text == "," && tokens[end+2].text == "(" {
			nextEnd := matchingDelimiter(tokens, end+2, "(", ")")
			if nextEnd < 0 {
				break
			}
			groups++
			end = nextEnd
		}
		if groups > 1 {
			result := append([]fingerprintToken{}, tokens[:firstEnd+1]...)
			result = append(result, fingerprintToken{kind: tokenPunctuation, text: ","}, fingerprintToken{kind: tokenMarker, text: "..."})
			result = append(result, tokens[end+1:]...)
			return result
		}
	}
	return tokens
}

func matchingDelimiter(tokens []fingerprintToken, start int, open, close string) int {
	depth := 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func renderFingerprint(tokens []fingerprintToken) string {
	var out strings.Builder
	for i, token := range tokens {
		if i > 0 && needsFingerprintSpace(tokens[i-1], token) {
			out.WriteByte(' ')
		}
		out.WriteString(token.text)
	}
	return strings.TrimSpace(out.String())
}

func needsFingerprintSpace(previous, current fingerprintToken) bool {
	if current.text == "," || current.text == ")" || current.text == "]" || current.text == "[" || current.text == ";" || current.text == "." || current.text == "::" {
		return false
	}
	if previous.text == "(" || previous.text == "[" || previous.text == "." || previous.text == "::" {
		return false
	}
	return true
}

func isLiteralKeyword(word string) bool {
	switch word {
	case "true", "false", "null":
		return true
	default:
		return false
	}
}

func startsComment(query string, i int) bool {
	return i+1 < len(query) && (query[i] == '-' && query[i+1] == '-' || query[i] == '/' && query[i+1] == '*')
}

func isTokenBoundary(query string, i int) bool {
	return isSpace(query[i]) || query[i] == '\'' || query[i] == '"' || isPunctuation(query[i]) || isOperator(query[i]) || startsComment(query, i)
}

func isPunctuation(c byte) bool {
	return c == '(' || c == ')' || c == '[' || c == ']' || c == ',' || c == ';' || c == '.'
}

func isOperator(c byte) bool {
	return strings.ContainsRune("+-*/<>=~!@#%^&|`?:", rune(c))
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isIdentifierByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'
}
