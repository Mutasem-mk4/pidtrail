package event

import "time"

type Kind string

const (
	KindDiagnostic Kind = "diagnostic"
	KindProcess    Kind = "process"
	KindFile       Kind = "file"
	KindNetwork    Kind = "network"
	KindHTTP       Kind = "http"
)

type Direction string

const (
	DirectionUnknown  Direction = "unknown"
	DirectionOutbound Direction = "outbound"
	DirectionInbound  Direction = "inbound"
)

type Source string

const (
	SourceKernelMetadata Source = "kernel-metadata"
	SourceUserspace      Source = "userspace"
)

type HTTPMessage struct {
	Type          string            `json:"type,omitempty"`
	Method        string            `json:"method,omitempty"`
	Path          string            `json:"path,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	Version       string            `json:"version,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	BodyPreview   string            `json:"body_preview,omitempty"`
	BodyBytes     int               `json:"body_bytes,omitempty"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
}

type Event struct {
	Time       time.Time         `json:"time"`
	Kind       Kind              `json:"kind"`
	Source     Source            `json:"source,omitempty"`
	Operation  string            `json:"operation,omitempty"`
	Message    string            `json:"message,omitempty"`
	PID        int               `json:"pid,omitempty"`
	TID        int               `json:"tid,omitempty"`
	Comm       string            `json:"comm,omitempty"`
	ParentPID  int               `json:"parent_pid,omitempty"`
	ChildPID   int               `json:"child_pid,omitempty"`
	ExitCode   int               `json:"exit_code,omitempty"`
	FD         int               `json:"fd,omitempty"`
	Direction  Direction         `json:"direction,omitempty"`
	Network    string            `json:"network,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	SrcAddr    string            `json:"src_addr,omitempty"`
	DstAddr    string            `json:"dst_addr,omitempty"`
	Path       string            `json:"path,omitempty"`
	Plaintext  string            `json:"plaintext,omitempty"`
	HTTP       *HTTPMessage      `json:"http,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func NewDiagnostic(msg string) Event {
	return Event{
		Time:    time.Now().UTC(),
		Kind:    KindDiagnostic,
		Source:  SourceUserspace,
		Message: msg,
	}
}
