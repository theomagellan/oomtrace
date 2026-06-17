package intake

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var fixedOSInfo = OSInfo{
	Architecture: "amd64",
	Bitness:      "64-bit",
	OSType:       "Linux",
	Version:      "6.8.0-test",
}

func makeMeta(service string) *samples.TraceEventMeta {
	return &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(time.Date(2024, 12, 5, 0, 0, 0, 0, time.UTC).UnixNano()),
		Comm:           libpf.Intern("victim"),
		PID:            libpf.PID(1234),
		APMServiceName: service,
		Origin:         support.TraceOriginOOM,
	}
}

func nativeFrames() libpf.Frames {
	var f libpf.Frames
	f.Append(&libpf.Frame{Type: libpf.KernelFrame, FunctionName: libpf.Intern("get_signal")})
	f.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		FunctionName:    libpf.Intern("malloc"),
		SourceFile:      libpf.Intern("malloc.c"),
		SourceLine:      42,
		AddressOrLineno: 0x7f1234,
	})
	f.Append(&libpf.Frame{
		Type:         libpf.NativeFrame,
		FunctionName: libpf.Intern("keep_allocating"),
		SourceFile:   libpf.Intern("victim.c"),
		SourceLine:   10,
	})
	return f
}

func pythonFrames() libpf.Frames {
	var f libpf.Frames
	f.Append(&libpf.Frame{Type: libpf.KernelFrame, FunctionName: libpf.Intern("get_signal")})
	f.Append(&libpf.Frame{Type: libpf.NativeFrame, FunctionName: libpf.Intern("PyEval_EvalFrameEx")})
	f.Append(&libpf.Frame{
		Type:         libpf.PythonFrame,
		FunctionName: libpf.Intern("keep_allocating"),
		SourceFile:   libpf.Intern("victim.py"),
		SourceLine:   14,
	})
	f.Append(&libpf.Frame{
		Type:         libpf.PythonFrame,
		FunctionName: libpf.Intern("main"),
		SourceFile:   libpf.Intern("victim.py"),
		SourceLine:   19,
	})
	return f
}

func goFrames() libpf.Frames {
	var f libpf.Frames
	f.Append(&libpf.Frame{Type: libpf.KernelFrame, FunctionName: libpf.Intern("get_signal")})
	f.Append(&libpf.Frame{
		Type:         libpf.GoFrame,
		FunctionName: libpf.Intern("main.keepAllocating"),
		SourceFile:   libpf.Intern("victim.go"),
		SourceLine:   15,
	})
	f.Append(&libpf.Frame{
		Type:         libpf.GoFrame,
		FunctionName: libpf.Intern("main.main"),
		SourceFile:   libpf.Intern("victim.go"),
		SourceLine:   25,
	})
	return f
}

func requireTag(t *testing.T, ddtags, key, value string) {
	t.Helper()
	tag := key + ":" + value
	for _, kv := range strings.Split(ddtags, ",") {
		if kv == tag {
			return
		}
	}
	t.Errorf("ddtags missing %q (got: %q)", tag, ddtags)
}

func requireTagKey(t *testing.T, ddtags, key string) {
	t.Helper()
	prefix := key + ":"
	for _, kv := range strings.Split(ddtags, ",") {
		if strings.HasPrefix(kv, prefix) {
			return
		}
	}
	t.Errorf("ddtags missing key %q (got: %q)", key, ddtags)
}

func TestBuild_RequiredFields(t *testing.T) {
	p, err := Build(&libpf.Trace{Frames: nativeFrames()}, makeMeta("mysvc"), fixedOSInfo)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if p.Timestamp == 0 {
		t.Error("timestamp must be non-zero")
	}
	if p.DDSource != DDSource {
		t.Errorf("ddsource = %q, want %q", p.DDSource, DDSource)
	}
	if p.DDTags == "" {
		t.Error("ddtags must not be empty")
	}
	if p.Error.SourceType != SourceType {
		t.Errorf("error.source_type = %q, want %q", p.Error.SourceType, SourceType)
	}
	if !p.Error.IsCrash {
		t.Error("error.is_crash must be true")
	}
	if p.Error.Type == "" {
		t.Error("error.type must not be empty")
	}
	if p.OSInfo.Architecture == "" || p.OSInfo.Bitness == "" || p.OSInfo.OSType == "" || p.OSInfo.Version == "" {
		t.Errorf("os_info has empty required field: %+v", p.OSInfo)
	}
	if p.SigInfo == nil {
		t.Fatal("sig_info must be present for OOM events")
	}
	if p.SigInfo.SISigno != OOMSigNo {
		t.Errorf("sig_info.si_signo = %d, want %d", p.SigInfo.SISigno, OOMSigNo)
	}
	if p.SigInfo.SISignoHumanReadable != OOMSigNoReadable {
		t.Errorf("sig_info.si_signo_human_readable = %q, want %q",
			p.SigInfo.SISignoHumanReadable, OOMSigNoReadable)
	}
}

func TestBuild_Timestamp(t *testing.T) {
	p, err := Build(&libpf.Trace{Frames: nativeFrames()}, makeMeta("svc"), fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}
	const wantMs = int64(1733356800000) // 2024-12-05T00:00:00Z
	if p.Timestamp != wantMs {
		t.Errorf("timestamp = %d, want %d", p.Timestamp, wantMs)
	}
}

func TestBuild_DDTags_RequiredKeys(t *testing.T) {
	p, err := Build(&libpf.Trace{Frames: nativeFrames()}, makeMeta("checkout"), fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{
		"service", "language_name", "data_schema_version",
		"incomplete", "is_crash", "uuid",
		"si_signo", "si_signo_human_readable", "si_code", "si_code_human_readable",
	} {
		requireTagKey(t, p.DDTags, k)
	}

	requireTag(t, p.DDTags, "service", "checkout")
	requireTag(t, p.DDTags, "is_crash", "true")
	requireTag(t, p.DDTags, "incomplete", "false")
	requireTag(t, p.DDTags, "data_schema_version", DataSchemaVersion)
	requireTag(t, p.DDTags, "si_signo_human_readable", OOMSigNoReadable)
}

func TestBuild_ServiceFallbacks(t *testing.T) {
	p, _ := Build(&libpf.Trace{Frames: nativeFrames()}, makeMeta(""), fixedOSInfo)
	requireTag(t, p.DDTags, "service", "unknown")

	meta := makeMeta("")
	meta.EnvVars = map[libpf.String]libpf.String{
		libpf.Intern("DD_SERVICE"): libpf.Intern("from-env"),
	}
	p2, _ := Build(&libpf.Trace{Frames: nativeFrames()}, meta, fixedOSInfo)
	requireTag(t, p2.DDTags, "service", "from-env")
}

func TestBuild_OptionalEnvTags(t *testing.T) {
	meta := makeMeta("svc")
	meta.EnvVars = map[libpf.String]libpf.String{
		libpf.Intern("DD_ENV"):     libpf.Intern("prod"),
		libpf.Intern("DD_VERSION"): libpf.Intern("1.2.3"),
	}
	p, err := Build(&libpf.Trace{Frames: nativeFrames()}, meta, fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}
	requireTag(t, p.DDTags, "env", "prod")
	requireTag(t, p.DDTags, "version", "1.2.3")
}

func TestBuild_Stack(t *testing.T) {
	p, err := Build(&libpf.Trace{Frames: nativeFrames()}, makeMeta("svc"), fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}

	st := p.Error.Stack
	if st == nil {
		t.Fatal("error.stack must be present when frames exist")
	}
	if st.Format != StackFormat {
		t.Errorf("stack.format = %q, want %q", st.Format, StackFormat)
	}
	if len(st.Frames) != 3 {
		t.Errorf("expected 3 frames (1 kernel + 2 native), got %d", len(st.Frames))
	}
	if st.Frames[0].Function != "get_signal" {
		t.Errorf("frame[0].function = %q, want %q", st.Frames[0].Function, "get_signal")
	}
	if st.Frames[1].Function != "malloc" {
		t.Errorf("frame[1].function = %q, want %q", st.Frames[1].Function, "malloc")
	}
	if st.Frames[1].File != "malloc.c" {
		t.Errorf("frame[1].file = %q", st.Frames[1].File)
	}
	if st.Frames[1].Line != 42 {
		t.Errorf("frame[1].line = %d, want 42", st.Frames[1].Line)
	}
}

func TestBuild_EmptyStack(t *testing.T) {
	p, err := Build(&libpf.Trace{}, makeMeta("svc"), fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}
	if p.Error.Stack != nil {
		t.Error("error.stack should be nil for an empty trace")
	}
}

func TestBuild_KernelOnlyStack(t *testing.T) {
	var kernelOnly libpf.Frames
	kernelOnly.Append(&libpf.Frame{Type: libpf.KernelFrame, FunctionName: libpf.Intern("get_signal")})

	p, err := Build(&libpf.Trace{Frames: kernelOnly}, makeMeta("svc"), fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}
	if p.Error.Stack == nil {
		t.Fatal("error.stack should be present when kernel frames exist")
	}
	if len(p.Error.Stack.Frames) != 1 {
		t.Errorf("expected 1 kernel frame, got %d", len(p.Error.Stack.Frames))
	}
	if p.Error.Stack.Frames[0].Function != "get_signal" {
		t.Errorf("frame[0].function = %q, want %q", p.Error.Stack.Frames[0].Function, "get_signal")
	}
}

func TestDetectLanguage(t *testing.T) {
	cases := []struct {
		name   string
		frames libpf.Frames
		want   string
	}{
		{"native only", nativeFrames(), "native"},
		{"python dominant", pythonFrames(), "python"},
		{"go only", goFrames(), "go"},
		{"kernel only", func() libpf.Frames {
			var f libpf.Frames
			f.Append(&libpf.Frame{Type: libpf.KernelFrame})
			return f
		}(), "native"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLanguage(tc.frames)
			if got != tc.want {
				t.Errorf("detectLanguage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuild_LanguageInDDTags(t *testing.T) {
	cases := []struct {
		name   string
		frames libpf.Frames
		want   string
	}{
		{"native", nativeFrames(), "native"},
		{"python", pythonFrames(), "python"},
		{"go", goFrames(), "go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Build(&libpf.Trace{Frames: tc.frames}, makeMeta("svc"), fixedOSInfo)
			if err != nil {
				t.Fatal(err)
			}
			requireTag(t, p.DDTags, "language_name", tc.want)
		})
	}
}

func TestBuild_JSONMarshal(t *testing.T) {
	p, err := Build(&libpf.Trace{Frames: pythonFrames()}, makeMeta("svc"), fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"timestamp", "ddsource", "ddtags", "error", "os_info", "sig_info"} {
		if _, ok := out[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}

func TestBuild_Fingerprint(t *testing.T) {
	trace := &libpf.Trace{Frames: nativeFrames()}
	meta := makeMeta("svc")

	p, err := Build(trace, meta, fixedOSInfo)
	if err != nil {
		t.Fatal(err)
	}
	if p.Error.Fingerprint == "" {
		t.Error("fingerprint must not be empty for non-empty stacks")
	}

	p2, _ := Build(trace, meta, fixedOSInfo)
	if p.Error.Fingerprint != p2.Error.Fingerprint {
		t.Error("fingerprint must be deterministic for the same stack")
	}

	p3, _ := Build(&libpf.Trace{Frames: pythonFrames()}, meta, fixedOSInfo)
	if p.Error.Fingerprint == p3.Error.Fingerprint {
		t.Error("fingerprint should differ for different stacks")
	}
}
