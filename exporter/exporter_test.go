package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/DataDog/oomtrace/intake"
)

func samplePayload(t *testing.T) *intake.Payload {
	t.Helper()
	var frames libpf.Frames
	frames.Append(&libpf.Frame{Type: libpf.KernelFrame, FunctionName: libpf.Intern("get_signal")})
	frames.Append(&libpf.Frame{
		Type:         libpf.NativeFrame,
		FunctionName: libpf.Intern("malloc"),
		SourceFile:   libpf.Intern("malloc.c"),
		SourceLine:   42,
	})

	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(time.Now().UnixNano()),
		APMServiceName: "testsvc",
		Origin:         support.TraceOriginOOM,
	}
	sys := intake.OSInfo{
		Architecture: "amd64",
		Bitness:      "64-bit",
		OSType:       "Linux",
		Version:      "6.8.0-test",
	}
	p, err := intake.Build(&libpf.Trace{Frames: frames}, meta, sys)
	if err != nil {
		t.Fatalf("intake.Build: %v", err)
	}
	return p
}

func assertValidJSON(t *testing.T, b []byte) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, b)
	}
	for _, key := range []string{"timestamp", "ddsource", "ddtags", "error", "os_info", "sig_info"} {
		if _, ok := out[key]; !ok {
			t.Errorf("exported JSON missing required key %q", key)
		}
	}
}

func TestWriterExporter(t *testing.T) {
	var buf bytes.Buffer
	exp := &writerExporter{w: &buf}
	if err := exp.Export(context.Background(), samplePayload(t)); err != nil {
		t.Fatalf("Export: %v", err)
	}
	assertValidJSON(t, buf.Bytes())
}

func TestFileExporter(t *testing.T) {
	path := t.TempDir() + "/oom.json"
	exp := &fileExporter{path: path}
	p := samplePayload(t)

	for i := range 2 {
		if err := exp.Export(context.Background(), p); err != nil {
			t.Fatalf("Export %d: %v", i, err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	var count int
	for dec.More() {
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			t.Fatalf("decode entry %d: %v", count, err)
		}
		for _, key := range []string{"timestamp", "ddsource", "ddtags", "error", "os_info", "sig_info"} {
			if _, ok := obj[key]; !ok {
				t.Errorf("entry %d missing required key %q", count, key)
			}
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 JSON entries in file, got %d", count)
	}
}

func TestNew_Stdout(t *testing.T) {
	exp := New("stdout")
	if _, ok := exp.(*writerExporter); !ok {
		t.Errorf("expected *writerExporter for 'stdout', got %T", exp)
	}
}

func TestNew_File(t *testing.T) {
	exp := New("file:///tmp/test.json")
	fe, ok := exp.(*fileExporter)
	if !ok {
		t.Fatalf("expected *fileExporter for file://, got %T", exp)
	}
	if fe.path != "/tmp/test.json" {
		t.Errorf("fileExporter.path = %q, want /tmp/test.json", fe.path)
	}
}

func TestNew_Direct(t *testing.T) {
	t.Setenv("DD_SITE", "datadoghq.eu")
	t.Setenv("DD_API_KEY", "test-key")

	exp := New("")
	de, ok := exp.(*directExporter)
	if !ok {
		t.Fatalf("expected *directExporter for empty endpoint, got %T", exp)
	}
	if de.url != "https://error-tracking-intake.datadoghq.eu/api/v2/errorsintake" {
		t.Errorf("unexpected URL: %s", de.url)
	}
	if de.apiKey != "test-key" {
		t.Errorf("unexpected apiKey: %s", de.apiKey)
	}
}

func TestNew_DirectDefaultSite(t *testing.T) {
	t.Setenv("DD_SITE", "")
	exp := New("")
	de, ok := exp.(*directExporter)
	if !ok {
		t.Fatalf("expected *directExporter, got %T", exp)
	}
	if de.url != "https://error-tracking-intake.datadoghq.com/api/v2/errorsintake" {
		t.Errorf("unexpected default URL: %s", de.url)
	}
}

func TestNew_CustomURL(t *testing.T) {
	exp := New("https://custom.intake.example.com/api/v2/errorsintake")
	if _, ok := exp.(*directExporter); !ok {
		t.Errorf("expected *directExporter for custom URL, got %T", exp)
	}
}
