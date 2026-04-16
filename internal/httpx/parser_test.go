package httpx

import (
	"strings"
	"testing"

	"github.com/pidtrail/pidtrail/internal/event"
)

func testParser() *Parser {
	return New(Options{
		CaptureBodies: true,
		MaxBodyBytes:  8,
		RedactHeaders: map[string]struct{}{
			"authorization": {},
		},
	})
}

func TestParserRequestPartialContentLength(t *testing.T) {
	p := testParser()
	part1 := []byte("POST /submit HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nhe")
	if events := p.Feed(event.DirectionOutbound, part1); len(events) != 0 {
		t.Fatalf("expected no complete events, got %d", len(events))
	}
	events := p.Feed(event.DirectionOutbound, []byte("llo"))
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].HTTP == nil || events[0].HTTP.BodyPreview != "hello" {
		t.Fatalf("unexpected body preview: %#v", events[0].HTTP)
	}
}

func TestParserChunkedResponse(t *testing.T) {
	p := testParser()
	resp := "" +
		"HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"4\r\nWiki\r\n" +
		"5\r\npedia\r\n" +
		"0\r\n\r\n"
	events := p.Feed(event.DirectionInbound, []byte(resp))
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if got := events[0].HTTP.BodyPreview; got != "Wikipedi" {
		t.Fatalf("unexpected chunked preview: %q", got)
	}
	if !events[0].HTTP.BodyTruncated {
		t.Fatal("expected truncation flag")
	}
}

func TestParserUnknownTraffic(t *testing.T) {
	p := testParser()
	events := p.Feed(event.DirectionOutbound, []byte("SSH-2.0-OpenSSH_9.7\r\n"))
	if len(events) != 0 {
		t.Fatalf("expected unknown traffic to remain unclassified")
	}
}

func TestParserTruncatesPreview(t *testing.T) {
	p := testParser()
	req := "" +
		"POST /x HTTP/1.1\r\n" +
		"Content-Length: 10\r\n\r\n" +
		"0123456789"
	events := p.Feed(event.DirectionOutbound, []byte(req))
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].HTTP.BodyPreview != "01234567" {
		t.Fatalf("unexpected preview: %q", events[0].HTTP.BodyPreview)
	}
	if !events[0].HTTP.BodyTruncated {
		t.Fatal("expected truncation flag")
	}
}

func TestParserRedactsHeaders(t *testing.T) {
	p := testParser()
	req := "" +
		"GET / HTTP/1.1\r\n" +
		"Authorization: secret\r\n\r\n"
	events := p.Feed(event.DirectionOutbound, []byte(req))
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if got := events[0].HTTP.Headers["Authorization"]; got != "[REDACTED]" {
		t.Fatalf("unexpected header value: %q", got)
	}
}

func TestParserMalformedContentLengthFallsBackToUnknown(t *testing.T) {
	p := testParser()
	req := "" +
		"POST /bad HTTP/1.1\r\n" +
		"Content-Length: nope\r\n\r\n"
	events := p.Feed(event.DirectionOutbound, []byte(req))
	if len(events) != 1 {
		t.Fatalf("expected one event even without body framing, got %d", len(events))
	}
	if !strings.EqualFold(events[0].HTTP.Method, "POST") {
		t.Fatalf("unexpected method: %q", events[0].HTTP.Method)
	}
}
