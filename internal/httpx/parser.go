package httpx

import (
	"bytes"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/pidtrail/pidtrail/internal/event"
)

const maxHeaderBytes = 64 * 1024

type Options struct {
	CaptureBodies bool
	MaxBodyBytes  int
	RedactHeaders map[string]struct{}
}

type Parser struct {
	opts   Options
	states map[event.Direction]*streamState
}

type streamState struct {
	buf []byte
}

type message struct {
	headerEnd int
	bodyNeed  int
	chunked   bool
	record    event.HTTPMessage
}

func New(opts Options) *Parser {
	if opts.MaxBodyBytes < 0 {
		opts.MaxBodyBytes = 0
	}
	return &Parser{
		opts: opts,
		states: map[event.Direction]*streamState{
			event.DirectionOutbound: {},
			event.DirectionInbound:  {},
		},
	}
}

func (p *Parser) Feed(direction event.Direction, data []byte) []event.Event {
	state, ok := p.states[direction]
	if !ok {
		return nil
	}
	state.buf = append(state.buf, data...)
	events := make([]event.Event, 0)
	for {
		record, consumed, ok := p.tryParseMessage(state.buf)
		if !ok {
			if len(state.buf) > maxHeaderBytes {
				state.buf = nil
			}
			break
		}
		state.buf = append([]byte(nil), state.buf[consumed:]...)
		events = append(events, event.Event{
			Kind:      event.KindHTTP,
			Source:    event.SourceUserspace,
			Direction: direction,
			Protocol:  "http/1.x",
			HTTP:      &record,
		})
	}
	return events
}

func (p *Parser) tryParseMessage(buf []byte) (event.HTTPMessage, int, bool) {
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return event.HTTPMessage{}, 0, false
	}
	headerBlock := string(buf[:headerEnd+4])
	lines := strings.Split(strings.TrimSuffix(headerBlock, "\r\n\r\n"), "\r\n")
	if len(lines) == 0 {
		return event.HTTPMessage{}, 0, false
	}
	startLine := lines[0]
	headers, ok := parseHeaders(lines[1:], p.opts.RedactHeaders)
	if !ok {
		return event.HTTPMessage{}, 0, false
	}

	record, bodyNeed, chunked, ok := classify(startLine, headers)
	if !ok {
		return event.HTTPMessage{}, 0, false
	}
	record.Headers = headers

	bodyStart := headerEnd + 4
	if chunked {
		bodyPreview, bodyBytes, truncated, consumed, complete := parseChunked(buf[bodyStart:], p.opts)
		if !complete {
			return event.HTTPMessage{}, 0, false
		}
		record.BodyPreview = bodyPreview
		record.BodyBytes = bodyBytes
		record.BodyTruncated = truncated
		return record, bodyStart + consumed, true
	}

	if len(buf[bodyStart:]) < bodyNeed {
		return event.HTTPMessage{}, 0, false
	}
	body := buf[bodyStart : bodyStart+bodyNeed]
	record.BodyPreview = previewBody(body, p.opts)
	record.BodyBytes = len(body)
	record.BodyTruncated = p.opts.CaptureBodies && len(body) > p.opts.MaxBodyBytes
	return record, bodyStart + bodyNeed, true
}

func parseHeaders(lines []string, redactions map[string]struct{}) (map[string]string, bool) {
	if len(lines) == 0 {
		return map[string]string{}, true
	}
	tp := textproto.MIMEHeader{}
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, false
		}
		key := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		tp.Add(key, value)
	}
	out := make(map[string]string, len(tp))
	for key, values := range tp {
		lower := strings.ToLower(key)
		if _, ok := redactions[lower]; ok {
			out[key] = "[REDACTED]"
			continue
		}
		out[key] = strings.Join(values, ", ")
	}
	return out, true
}

func classify(startLine string, headers map[string]string) (event.HTTPMessage, int, bool, bool) {
	if strings.HasPrefix(startLine, "HTTP/1.0 ") || strings.HasPrefix(startLine, "HTTP/1.1 ") {
		parts := strings.SplitN(startLine, " ", 3)
		if len(parts) < 2 {
			return event.HTTPMessage{}, 0, false, false
		}
		status, err := strconv.Atoi(parts[1])
		if err != nil {
			return event.HTTPMessage{}, 0, false, false
		}
		reason := ""
		if len(parts) == 3 {
			reason = parts[2]
		}
		bodyNeed, chunked := bodyMode(headers, true, status)
		return event.HTTPMessage{
			Type:       "response",
			StatusCode: status,
			Reason:     reason,
			Version:    parts[0],
		}, bodyNeed, chunked, true
	}
	parts := strings.SplitN(startLine, " ", 3)
	if len(parts) != 3 {
		return event.HTTPMessage{}, 0, false, false
	}
	if !strings.HasPrefix(parts[2], "HTTP/1.") {
		return event.HTTPMessage{}, 0, false, false
	}
	if !validMethod(parts[0]) {
		return event.HTTPMessage{}, 0, false, false
	}
	bodyNeed, chunked := bodyMode(headers, false, 0)
	return event.HTTPMessage{
		Type:    "request",
		Method:  parts[0],
		Path:    parts[1],
		Version: parts[2],
	}, bodyNeed, chunked, true
}

func validMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	default:
		return false
	}
}

func bodyMode(headers map[string]string, response bool, status int) (int, bool) {
	if response && (status >= 100 && status < 200 || status == 204 || status == 304) {
		return 0, false
	}
	for key, value := range headers {
		if strings.EqualFold(key, "Transfer-Encoding") && strings.Contains(strings.ToLower(value), "chunked") {
			return 0, true
		}
	}
	for key, value := range headers {
		if strings.EqualFold(key, "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 {
				return 0, false
			}
			return n, false
		}
	}
	return 0, false
}

func parseChunked(buf []byte, opts Options) (string, int, bool, int, bool) {
	var body bytes.Buffer
	total := 0
	consumed := 0
	for {
		lineEnd := bytes.Index(buf[consumed:], []byte("\r\n"))
		if lineEnd < 0 {
			return "", 0, false, 0, false
		}
		line := string(buf[consumed : consumed+lineEnd])
		sizeField := strings.SplitN(line, ";", 2)[0]
		size, err := strconv.ParseInt(strings.TrimSpace(sizeField), 16, 64)
		if err != nil || size < 0 {
			return "", 0, false, 0, false
		}
		consumed += lineEnd + 2
		if size == 0 {
			if len(buf[consumed:]) < 2 {
				return "", 0, false, 0, false
			}
			if bytes.HasPrefix(buf[consumed:], []byte("\r\n")) {
				consumed += 2
			} else {
				trailerEnd := bytes.Index(buf[consumed:], []byte("\r\n\r\n"))
				if trailerEnd < 0 {
					return "", 0, false, 0, false
				}
				consumed += trailerEnd + 4
			}
			return previewBody(body.Bytes(), opts), total, opts.CaptureBodies && total > opts.MaxBodyBytes, consumed, true
		}
		if len(buf[consumed:]) < int(size)+2 {
			return "", 0, false, 0, false
		}
		if opts.CaptureBodies && body.Len() < opts.MaxBodyBytes {
			remaining := opts.MaxBodyBytes - body.Len()
			chunk := buf[consumed : consumed+int(size)]
			if len(chunk) > remaining {
				chunk = chunk[:remaining]
			}
			_, _ = body.Write(chunk)
		}
		total += int(size)
		consumed += int(size)
		if !bytes.Equal(buf[consumed:consumed+2], []byte("\r\n")) {
			return "", 0, false, 0, false
		}
		consumed += 2
	}
}

func previewBody(body []byte, opts Options) string {
	if !opts.CaptureBodies || len(body) == 0 {
		return ""
	}
	limit := opts.MaxBodyBytes
	if limit < 0 {
		limit = 0
	}
	if len(body) > limit {
		body = body[:limit]
	}
	var b strings.Builder
	for _, ch := range body {
		if ch >= 0x20 && ch <= 0x7e || ch == '\n' || ch == '\r' || ch == '\t' {
			b.WriteByte(ch)
			continue
		}
		b.WriteString(fmt.Sprintf("\\x%02x", ch))
	}
	return b.String()
}
