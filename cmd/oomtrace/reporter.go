package main

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/DataDog/oomtrace/exporter"
	"github.com/DataDog/oomtrace/intake"
)

type oomReporter struct {
	events   chan oomEvent
	sysInfo  intake.OSInfo
	exporter exporter.Exporter
}

type oomEvent struct {
	trace *libpf.Trace
	meta  *samples.TraceEventMeta
}

func newOOMReporter(sys intake.OSInfo, exp exporter.Exporter) *oomReporter {
	return &oomReporter{
		events:   make(chan oomEvent, 64),
		sysInfo:  sys,
		exporter: exp,
	}
}

func (r *oomReporter) Start(ctx context.Context) error {
	go r.run(ctx)
	return nil
}

func (r *oomReporter) Stop() {}

func (r *oomReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	if meta.Origin != support.TraceOriginOOM {
		return nil
	}
	select {
	case r.events <- oomEvent{trace: trace, meta: meta}:
	default:
		slog.Warn("OOM event dropped: channel full")
	}
	return nil
}

func (r *oomReporter) run(ctx context.Context) {
	for {
		select {
		case ev := <-r.events:
			r.handle(ctx, ev)
		case <-ctx.Done():
			return
		}
	}
}

func (r *oomReporter) handle(ctx context.Context, ev oomEvent) {
	p, err := intake.Build(ev.trace, ev.meta, r.sysInfo)
	if err != nil {
		slog.Error("failed to build OOM payload", "pid", ev.meta.PID, "err", err)
		return
	}
	if err := r.exporter.Export(ctx, p); err != nil {
		slog.Error("failed to export OOM event", "pid", ev.meta.PID, "err", err)
	}
}
