package certs

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"unicode/utf8"
)

const (
	rustCertificate = "CertificateDer::from_slice"
	quotedPEM       = "\"-----BEGIN CERTIFICATE-----"
	codeSource      = "unsupported_source"
	formatSource    = "source"
	templatePEM     = "js-template-pem"
	decimalDigits   = 10
	hexByteDigits   = 2
)

type sourceSpan struct {
	start, end int
}

func (s *scanner) sourceCertificates(data []byte, collection *Collection) []sourceSpan {
	templateCandidate := bytes.ContainsRune(data, '`') && bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----"))
	if !bytes.Contains(data, []byte(rustCertificate)) && !bytes.Contains(data, []byte(quotedPEM)) && !templateCandidate {
		return nil
	}
	var templates []sourceSpan
	for pos := 0; pos < len(data); {
		pos = sourceSpace(data, pos)
		if pos == len(data) {
			break
		}
		var more bool
		switch {
		case bytes.HasPrefix(data[pos:], []byte(rustCertificate)) && (pos == 0 || !sourceIdentifier(data[pos-1])):
			pos, more = s.rustSource(data, pos, collection)
		case quotedPEMStart(data[pos:]) && (pos == 0 || !sourceIdentifier(data[pos-1])):
			pos, more = s.quotedSource(data, pos, collection)
		case bytes.HasPrefix(data[pos:], []byte("``")):
			for pos < len(data) && data[pos] == '`' {
				pos++
			}
			more = true
		case data[pos] == '`':
			start := pos
			pos, more = s.templateSource(data, pos, collection)
			if bytes.Contains(data[start:pos], []byte("-----BEGIN CERTIFICATE-----")) {
				templates = append(templates, sourceSpan{start, pos})
			}
		case data[pos] == '"':
			_, pos, _ = sourceString(data, pos, false, false)
			more = true
		default:
			pos++
			more = true
		}
		if !more {
			return templates
		}
	}
	return templates
}

func (s *scanner) templateSource(data []byte, start int, collection *Collection) (int, bool) {
	end := start + 1
	for end < len(data) && data[end] != '`' {
		if data[end] == '\\' {
			end++
		}
		end++
	}
	end = min(end, len(data))
	body := data[start+1 : end]
	closed := end < len(data)
	if closed {
		end++
	}
	if !templateCertificatePEM(body) {
		return end, true
	}
	collection.Format = formatSource
	if !closed || bytes.ContainsRune(body, '\\') || bytes.Contains(body, []byte("${")) {
		s.problem(collection, codeSource, fmt.Sprintf("template certificate at offset %d: escapes, interpolation or missing closing backtick", start))
		return end, true
	}
	return end, s.sourcePEM(body, start, collection, templatePEM)
}

func templateCertificatePEM(body []byte) bool {
	for _, newline := range []string{"\n", "\r\n", `\n`, `\r\n`} {
		if bytes.Contains(body, []byte("-----BEGIN CERTIFICATE-----"+newline)) {
			return true
		}
	}
	return false
}

func (s *scanner) rustSource(data []byte, start int, collection *Collection) (int, bool) {
	pos := sourceSpace(data, start+len(rustCertificate))
	if pos == len(data) || data[pos] != '(' {
		return pos, true
	}
	pos = sourceSpace(data, pos+1)
	if !bytes.HasPrefix(data[pos:], []byte("b\"")) {
		return pos, true
	}
	collection.Format = formatSource
	der, end, err := sourceString(data, pos+1, true, true)
	if err != nil {
		s.problem(collection, codeSource, fmt.Sprintf("Rust certificate at offset %d: %v", start, err))
		return end, true
	}
	end = sourceSpace(data, end)
	if end == len(data) || data[end] != ')' {
		s.problem(collection, codeSource, fmt.Sprintf("unfinished Rust certificate constructor at offset %d", start))
		return end, true
	}
	offset := int64(start)
	return end + 1, s.addCertificate(der, collection, Occurrence{Offset: &offset, EntryType: "rust-byte-der"})
}

func (s *scanner) quotedSource(data []byte, start int, collection *Collection) (int, bool) {
	collection.Format = formatSource
	pos := start
	var decoded []byte
	for pos < len(data) && data[pos] == '"' {
		part, end, err := sourceString(data, pos, true, false)
		if err != nil {
			s.problem(collection, codeSource, fmt.Sprintf("quoted certificate at offset %d: %v", start, err))
			return end, true
		}
		decoded = append(decoded, part...)
		pos = sourceSpace(data, end)
	}
	return pos, s.sourcePEM(decoded, start, collection, "c-string-pem")
}

func (s *scanner) sourcePEM(decoded []byte, start int, collection *Collection, entryType string) bool {
	const begin = "-----BEGIN CERTIFICATE-----"
	for len(bytes.TrimSpace(decoded)) > 0 {
		decoded = bytes.TrimSpace(decoded)
		end := len(decoded)
		if len(decoded) > len(begin) {
			if next := bytes.Index(decoded[len(begin):], []byte(begin)); next >= 0 {
				end = len(begin) + next
			}
		}
		block, rest := pem.Decode(decoded[:end])
		if !bytes.HasPrefix(decoded, []byte(begin)) || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			s.problem(collection, codeMalformed, fmt.Sprintf("invalid quoted PEM certificate at offset %d", start))
		} else {
			offset := int64(start)
			if !s.addCertificate(block.Bytes, collection, Occurrence{Offset: &offset, EntryType: entryType}) {
				return false
			}
		}
		decoded = decoded[end:]
	}
	return true
}

func sourceIdentifier(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}

func quotedPEMStart(data []byte) bool {
	return bytes.HasPrefix(data, []byte(quotedPEM+`\n`)) || bytes.HasPrefix(data, []byte(quotedPEM+`\r\n`))
}

func sourceSpace(data []byte, pos int) int {
	for pos < len(data) {
		switch {
		case bytes.ContainsRune([]byte(" \t\r\n"), rune(data[pos])):
			pos++
		case bytes.HasPrefix(data[pos:], []byte("//")):
			end := bytes.IndexByte(data[pos:], '\n')
			if end < 0 {
				return len(data)
			}
			pos += end + 1
		case bytes.HasPrefix(data[pos:], []byte("/*")):
			pos = sourceComment(data, pos+len("/*"))
		default:
			return pos
		}
	}
	return pos
}

func sourceComment(data []byte, pos int) int {
	for depth := 1; pos < len(data); {
		switch {
		case bytes.HasPrefix(data[pos:], []byte("/*")):
			depth++
			pos += 2
		case bytes.HasPrefix(data[pos:], []byte("*/")):
			depth--
			pos += 2
			if depth == 0 {
				return pos
			}
		default:
			pos++
		}
	}
	return len(data)
}

// Only the ASCII escapes used by generated certificate literals are decoded.
func sourceString(data []byte, start int, decode, rust bool) ([]byte, int, error) {
	for pos := start + 1; pos < len(data); pos++ {
		b := data[pos]
		if b == '"' {
			if !decode {
				return nil, pos + 1, nil
			}
			result, err := decodeSourceString(data[start+1:pos], rust)
			return result, pos + 1, err
		}
		if b == '\n' || b == '\r' {
			return nil, pos + 1, fmt.Errorf("unescaped newline in literal")
		}
		if b == '\\' {
			pos++
		}
	}
	return nil, len(data), fmt.Errorf("unterminated literal")
}

func decodeSourceString(data []byte, rust bool) ([]byte, error) {
	result := make([]byte, 0, len(data))
	for pos := 0; pos < len(data); pos++ {
		b := data[pos]
		if b >= utf8.RuneSelf || b == '\n' || b == '\r' {
			return nil, fmt.Errorf("non-ASCII byte or unescaped newline in literal")
		}
		if b == '\\' {
			var err error
			b, pos, err = sourceEscape(data, pos+1, rust)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, b)
	}
	return result, nil
}

func sourceEscape(data []byte, pos int, rust bool) (byte, int, error) {
	if pos < len(data) {
		switch b := data[pos]; b {
		case 'n':
			return '\n', pos, nil
		case 'r':
			return '\r', pos, nil
		case 't':
			return '\t', pos, nil
		case '\\', '"', '\'':
			return b, pos, nil
		case '0':
			if rust {
				return 0, pos, nil
			}
		case 'x':
			if rust && pos+2 < len(data) && hexDigit(data[pos+1]) >= 0 && hexDigit(data[pos+2]) >= 0 {
				return byte(hexDigit(data[pos+1])*hexRadix + hexDigit(data[pos+2])), pos + hexByteDigits, nil
			}
		}
	}
	return 0, pos, fmt.Errorf("unsupported or invalid escape")
}

func hexDigit(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + decimalDigits
	case b >= 'A' && b <= 'F':
		return int(b-'A') + decimalDigits
	default:
		return -1
	}
}
