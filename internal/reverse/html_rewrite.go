package reverse

import "bytes"

// rewriteHTMLRootAbsolutePaths rewrites root-absolute URLs in HTML while keeping inline scripts safe.
//
// HTML needs generic quote/url() rewriting for attributes, but applying that rewrite to inline JS can
// corrupt regex literals (e.g. .replace(/"/g, ...)). This function rewrites:
//   - non-script regions using rewriteRootAbsolutePaths
//   - <script>...</script> bodies using rewriteJavaScriptRootAbsolutePaths
func rewriteHTMLRootAbsolutePaths(in []byte, prefix string) []byte {
	if len(in) == 0 {
		return in
	}
	if normalizedPrefixBytes(prefix) == nil {
		return in
	}

	open := indexHTMLScriptOpen(in, 0)
	if open < 0 {
		return rewriteRootAbsolutePaths(in, prefix)
	}

	var (
		out      bytes.Buffer
		last     int
		modified bool
	)
	out.Grow(len(in) + len(in)/16)

	for open >= 0 {
		tagEnd := findHTMLTagEnd(in, open)
		if tagEnd < 0 {
			return rewriteRootAbsolutePaths(in, prefix)
		}

		contentStart := tagEnd + 1
		close := indexHTMLScriptClose(in, contentStart)
		if close < 0 {
			return rewriteRootAbsolutePaths(in, prefix)
		}

		before := in[last:contentStart]
		beforeRewritten := rewriteRootAbsolutePaths(before, prefix)
		if !bytes.Equal(before, beforeRewritten) {
			modified = true
		}
		out.Write(beforeRewritten)

		script := in[contentStart:close]
		scriptRewritten := rewriteJavaScriptRootAbsolutePaths(script, prefix)
		if !bytes.Equal(script, scriptRewritten) {
			modified = true
		}
		out.Write(scriptRewritten)

		last = close
		open = indexHTMLScriptOpen(in, last)
	}

	tail := in[last:]
	tailRewritten := rewriteRootAbsolutePaths(tail, prefix)
	if !bytes.Equal(tail, tailRewritten) {
		modified = true
	}
	out.Write(tailRewritten)

	if !modified {
		return in
	}
	return out.Bytes()
}

func indexHTMLScriptOpen(in []byte, from int) int {
	const needle = "script"
	for i := from; i+1+len(needle) <= len(in); i++ {
		if in[i] != '<' {
			continue
		}
		if i+1 < len(in) && in[i+1] == '/' {
			continue
		}
		j := i + 1
		if lowerASCII(in[j]) != 's' || lowerASCII(in[j+1]) != 'c' || lowerASCII(in[j+2]) != 'r' ||
			lowerASCII(in[j+3]) != 'i' || lowerASCII(in[j+4]) != 'p' || lowerASCII(in[j+5]) != 't' {
			continue
		}
		end := j + len(needle)
		if end >= len(in) {
			return i
		}
		switch in[end] {
		case '>', '/':
			return i
		default:
			if isSpace(in[end]) {
				return i
			}
		}
	}
	return -1
}

func indexHTMLScriptClose(in []byte, from int) int {
	const needle = "script"
	for i := from; i+2+len(needle) <= len(in); i++ {
		if in[i] != '<' {
			continue
		}
		if in[i+1] != '/' {
			continue
		}
		j := i + 2
		if lowerASCII(in[j]) != 's' || lowerASCII(in[j+1]) != 'c' || lowerASCII(in[j+2]) != 'r' ||
			lowerASCII(in[j+3]) != 'i' || lowerASCII(in[j+4]) != 'p' || lowerASCII(in[j+5]) != 't' {
			continue
		}
		end := j + len(needle)
		if end >= len(in) {
			return i
		}
		switch in[end] {
		case '>', '/':
			return i
		default:
			if isSpace(in[end]) {
				return i
			}
		}
	}
	return -1
}

func findHTMLTagEnd(in []byte, start int) int {
	var quote byte
	for i := start; i < len(in); i++ {
		c := in[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '>':
			return i
		default:
		}
	}
	return -1
}
