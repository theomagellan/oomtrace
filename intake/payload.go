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
)

// sigName maps signal numbers to their POSIX names.
var sigName = map[int]string{
	4:  "SIGILL",
	6:  "SIGABRT",
	7:  "SIGBUS",
	8:  "SIGFPE",
	9:  "SIGKILL",
	11: "SIGSEGV",
}

// sigInfo returns the SigInfo for a given signal number.
// OOM kills (SIGKILL) always have SI_KERNEL as the si_code.
// For other signals we don't have si_code from the eBPF side yet, so we use 0.
func sigInfoFor(signo int) *SigInfo {
	name, ok := sigName[signo]
	if !ok {
		name = fmt.Sprintf("SIG%d", signo)
	}
	si := &SigInfo{
		SISigno:              signo,
		SISignoHumanReadable: name,
	}
	if signo == 9 { // SIGKILL from OOM killer is always SI_KERNEL
		si.SICode = 128
		si.SICodeHumanReadable = "SI_KERNEL"
	}
	return si
}

func crashMessage(signo int) string {
	switch signo {
	case 9:
		return "Process killed by the OOM killer"
	default:
		name := sigName[signo]
		if name == "" {
			name = fmt.Sprintf("signal %d", signo)
		}
		return "Process terminated with " + name
	}
}

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

// Build constructs an RFC 0013 payload from a captured crash trace.
func Build(trace *libpf.Trace, meta *samples.TraceEventMeta, sys OSInfo) (*Payload, error) {
	id := uuid.New().String()
	tsMs := int64(meta.Timestamp) / int64(time.Millisecond)
	signo := int(meta.Value)

	lang := detectLanguage(trace.Frames)
	service := resolveService(meta)
	env := envVar(meta.EnvVars, "DD_ENV")
	version := envVar(meta.EnvVars, "DD_VERSION")
	fp := fingerprint(trace.Frames)
	sig := sigInfoFor(signo)

	return &Payload{
		Timestamp: tsMs,
		DDSource:  DDSource,
		DDTags:    buildDDTags(id, service, env, version, lang, fp, sig),
		Error: ErrorObject{
			Type:        sig.SISignoHumanReadable,
			Message:     crashMessage(signo),
			Stack:       buildStack(trace.Frames),
			IsCrash:     true,
			Fingerprint: fp,
			SourceType:  SourceType,
		},
		OSInfo:  sys,
		SigInfo: sig,
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

func buildDDTags(id, service, env, version, lang, fp string, sig *SigInfo) string {
	tags := []string{
		"service:" + service,
		"language_name:" + lang,
		"data_schema_version:" + DataSchemaVersion,
		"incomplete:false",
		"is_crash:true",
		"uuid:" + id,
		"from_ebpf:yes",
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
		// RFC makes no mention of HTL, how do they handle 'redacted' gobuildIDs?
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

// fingerprint returns a short hex hash over the first 5 non-kernel frames that
// carry identifying information, for deduplication. Kernel frames are excluded
// because they are identical across all OOM kills for the same interrupt path.
// For frames without a resolved symbol, (buildID, relativeAddress) is used as
// a stable fallback so that native-only stacks still produce meaningful hashes.
// Returns "" when no informative frames are found.
func fingerprint(frames libpf.Frames) string {
	h := sha256.New()
	n := 0
	for _, fh := range frames {
		if n >= 5 {
			break
		}
		f := fh.Value()
		if f.Type == libpf.KernelFrame {
			continue
		}
		if name := f.FunctionName.String(); name != "" {
			fmt.Fprintf(h, "fn:%s\n", name)
			n++
		} else if f.Mapping.Valid() {
			file := f.Mapping.Value().File.Value()
			bid := file.GnuBuildID
			if bid == "" {
				bid = file.GoBuildID
			}
			if bid != "" && f.AddressOrLineno > 0 {
				fmt.Fprintf(h, "elf:%s:0x%x\n", bid, f.AddressOrLineno)
				n++
			}
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
