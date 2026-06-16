package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/DataDog/oomtrace/intake"
)

type Exporter interface {
	Export(ctx context.Context, p *intake.Payload) error
}

// New creates an Exporter from an endpoint string.
//
// Supported forms:
//
//	""                      → direct submission using DD_API_KEY + DD_SITE (default)
//	"stdout"                → JSON to stdout (debug / manual testing)
//	"file:///path/to/file"  → append JSON to file (integration tests)
//	any other string        → treated as the full intake URL (overrides DD_SITE)
func New(endpoint string) Exporter {
	switch {
	case endpoint == "":
		site := os.Getenv("DD_SITE")
		if site == "" {
			site = "datadoghq.com"
		}
		return &directExporter{
			url:    "https://error-tracking-intake." + site + "/api/v2/errorsintake",
			apiKey: os.Getenv("DD_API_KEY"),
			client: &http.Client{},
		}
	case endpoint == "stdout":
		return &writerExporter{w: os.Stdout}
	case strings.HasPrefix(endpoint, "file://"):
		return &fileExporter{path: strings.TrimPrefix(endpoint, "file://")}
	default:
		return &directExporter{
			url:    endpoint,
			apiKey: os.Getenv("DD_API_KEY"),
			client: &http.Client{},
		}
	}
}

// directExporter sends the payload directly to the Errors Intake API using DD-API-KEY.
type directExporter struct {
	url    string
	apiKey string
	client *http.Client
}

func (e *directExporter) Export(ctx context.Context, p *intake.Payload) error {
	if e.apiKey == "" {
		return fmt.Errorf("DD_API_KEY is not set")
	}

	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, b)
	}
	return nil
}

// writerExporter writes indented JSON to any io.Writer.
type writerExporter struct {
	w io.Writer
}

func (e *writerExporter) Export(_ context.Context, p *intake.Payload) error {
	enc := json.NewEncoder(e.w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// fileExporter appends one JSON payload per call to a file.
// Useful as a sink for integration tests via OOMTRACE_ENDPOINT=file:///tmp/oom.json.
type fileExporter struct {
	path string
}

func (e *fileExporter) Export(ctx context.Context, p *intake.Payload) error {
	f, err := os.OpenFile(e.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", e.path, err)
	}
	defer f.Close()
	return (&writerExporter{w: f}).Export(ctx, p)
}
