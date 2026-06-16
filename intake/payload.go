package intake

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

const (
	DataSchemaVersion = "1.8"
	StackFormat       = "Datadog Crashtracker 1.0"
	SourceType        = "Crashtracking"
	DDSource          = "crashtracker"

	OOMSigNo           = 9
	OOMSigNoReadable   = "SIGKILL"
	OOMSICode          = 128 // SI_KERNEL: OOM kills always originate from kernel context
	OOMSICodeReadable  = "SI_KERNEL"
)

// Payload is the RFC 0013 top-level structure sent to /api/v2/errorsintake.
type Payload struct {
	Timestamp int64       `json:"timestamp"` // ms since epoch
	DDSource  string      `json:"ddsource"`
	DDTags    string      `json:"ddtags"`
	Error     ErrorObject `json:"error"`
	TraceID   *string     `json:"trace_id,omitempty"`
	OSInfo    OSInfo      `json:"os_info"`
	SigInfo   *SigInfo    `json:"sig_info,omitempty"`
}

type ErrorObject struct {
	Type        string      `json:"type"`
	Message     string      `json:"message,omitempty"`
	Stack       *StackTrace `json:"stack,omitempty"`
	IsCrash     bool        `json:"is_crash"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	SourceType  string      `json:"source_type"`
}

type StackTrace struct {
	Format string       `json:"format"`
	Frames []StackFrame `json:"frames"`
}

type StackFrame struct {
	Function        string `json:"function,omitempty"`
	File            string `json:"file,omitempty"`
	Line            int    `json:"line,omitempty"`
	Column          int    `json:"column,omitempty"`
	BuildID         string `json:"build_id,omitempty"`
	BuildIDType     string `json:"build_id_type,omitempty"`
	Path            string `json:"path,omitempty"`
	RelativeAddress string `json:"relative_address,omitempty"`
	FileType        string `json:"file_type,omitempty"`
}

type SigInfo struct {
	SICode               int    `json:"si_code"`
	SICodeHumanReadable  string `json:"si_code_human_readable"`
	SISigno              int    `json:"si_signo"`
	SISignoHumanReadable string `json:"si_signo_human_readable"`
}

// Build constructs an RFC 0013 payload from a captured OOM trace.
func Build(trace *libpf.Trace, meta *samples.TraceEventMeta, sys OSInfo) (*Payload, error) {
	id := uuid.New().String()
	tsMs := int64(meta.Timestamp) / int64(time.Millisecond)

	userFrames := userSpaceFrames(trace.Frames)
	lang := detectLanguage(trace.Frames)
	service := resolveService(meta)
	env := envVar(meta.EnvVars, "DD_ENV")
	version := envVar(meta.EnvVars, "DD_VERSION")
	fp := fingerprint(userFrames)

	return &Payload{
		Timestamp: tsMs,
		DDSource:  DDSource,
		DDTags:    buildDDTags(id, service, env, version, lang, fp),
		Error: ErrorObject{
			Type:        OOMSigNoReadable,
			Message:     "Process killed by the OOM killer",
			Stack:       buildStack(userFrames),
			IsCrash:     true,
			Fingerprint: fp,
			SourceType:  SourceType,
		},
		OSInfo: sys,
		SigInfo: &SigInfo{
			SISigno:              OOMSigNo,
			SISignoHumanReadable: OOMSigNoReadable,
			SICode:               OOMSICode,
			SICodeHumanReadable:  OOMSICodeReadable,
		},
	}, nil
}

func resolveService(meta *samples.TraceEventMeta) string {
	if meta.APMServiceName != "" {
		return meta.APMServiceName
	}
	if s := envVar(meta.EnvVars, "DD_SERVICE"); s != "" {
		return s
	}
	return "unknown"
}

func envVar(vars map[libpf.String]libpf.String, key string) string {
	if vars == nil {
		return ""
	}
	if v, ok := vars[libpf.Intern(key)]; ok {
		return v.String()
	}
	return ""
}

func buildDDTags(id, service, env, version, lang, fp string) string {
	tags := []string{
		"service:" + service,
		"language_name:" + lang,
		"data_schema_version:" + DataSchemaVersion,
		"incomplete:false",
		"is_crash:true",
		"uuid:" + id,
		fmt.Sprintf("si_signo:%d", OOMSigNo),
		"si_signo_human_readable:" + OOMSigNoReadable,
		fmt.Sprintf("si_code:%d", OOMSICode),
		"si_code_human_readable:" + OOMSICodeReadable,
	}
	if env != "" {
		tags = append(tags, "env:"+env)
	}
	if version != "" {
		tags = append(tags, "version:"+version)
	}
	if fp != "" {
		tags = append(tags, "fingerprint:"+fp)
	}
	return strings.Join(tags, ",")
}

func userSpaceFrames(frames libpf.Frames) libpf.Frames {
	start := 0
	for start < len(frames) && frames[start].Value().Type == libpf.KernelFrame {
		start++
	}
	return frames[start:]
}

func buildStack(frames libpf.Frames) *StackTrace {
	if len(frames) == 0 {
		return nil
	}
	sf := make([]StackFrame, 0, len(frames))
	for _, h := range frames {
		sf = append(sf, toStackFrame(h.Value()))
	}
	return &StackTrace{
		Format: StackFormat,
		Frames: sf,
	}
}

func toStackFrame(f libpf.Frame) StackFrame {
	sf := StackFrame{
		Function: f.FunctionName.String(),
		File:     f.SourceFile.String(),
	}
	if f.SourceLine > 0 {
		sf.Line = int(f.SourceLine)
	}
	if f.SourceColumn > 0 {
		sf.Column = int(f.SourceColumn)
	}
	if f.Mapping.Valid() {
		m := f.Mapping.Value()
		file := m.File.Value()
		sf.Path = file.FileName.String()
		sf.FileType = "ELF"
		switch {
		case file.GnuBuildID != "":
			sf.BuildID = file.GnuBuildID
			sf.BuildIDType = "GNU"
		case file.GoBuildID != "":
			sf.BuildID = file.GoBuildID
			sf.BuildIDType = "GO"
		}
		if f.AddressOrLineno > 0 {
			sf.RelativeAddress = fmt.Sprintf("0x%x", f.AddressOrLineno)
		}
	}
	return sf
}

// detectLanguage returns the language_name tag value for the dominant non-kernel
// frame type in the stack, falling back to "native".
func detectLanguage(frames libpf.Frames) string {
	counts := map[libpf.FrameType]int{}
	for _, h := range frames {
		ft := h.Value().Type
		if ft != libpf.KernelFrame {
			counts[ft]++
		}
	}

	best := libpf.NativeFrame
	bestCount := 0
	for ft, c := range counts {
		if ft == libpf.NativeFrame {
			continue
		}
		if c > bestCount {
			best = ft
			bestCount = c
		}
	}
	return frameTypeLanguage(best)
}

func frameTypeLanguage(ft libpf.FrameType) string {
	switch ft {
	case libpf.GoFrame:
		return "go"
	case libpf.PythonFrame:
		return "python"
	case libpf.HotSpotFrame:
		return "jvm"
	case libpf.RubyFrame:
		return "ruby"
	case libpf.DotnetFrame:
		return "dotnet"
	case libpf.V8Frame:
		return "nodejs"
	case libpf.PHPFrame, libpf.PHPJITFrame:
		return "php"
	case libpf.PerlFrame:
		return "perl"
	default:
		return "native"
	}
}

// fingerprint returns a short hex hash of the top userspace frame function names
// for deduplication. Returns "" for empty stacks.
func fingerprint(frames libpf.Frames) string {
	if len(frames) == 0 {
		return ""
	}
	limit := 5
	if len(frames) < limit {
		limit = len(frames)
	}
	h := sha256.New()
	for _, fh := range frames[:limit] {
		fmt.Fprintf(h, "%s\n", fh.Value().FunctionName.String())
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
