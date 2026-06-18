package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/DataDog/oomtrace/exporter"
	"github.com/DataDog/oomtrace/intake"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "oomtrace: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Probe that eBPF is available, mirroring what internal/controller does before NewTracer.
	if _, _, errno := unix.Syscall(unix.SYS_BPF, 0, 0, 0); errno == unix.ENOSYS {
		return fmt.Errorf("eBPF syscall not available")
	}

	metrics.Start(noop.Meter{})

	sys, err := intake.CollectOSInfo()
	if err != nil {
		return fmt.Errorf("collect OS info: %w", err)
	}

	exp := exporter.New(os.Getenv("OOMTRACE_ENDPOINT"))
	rep := newOOMReporter(sys, exp)

	intervals := times.New(
		60*time.Second, // reportInterval (unused for event-driven, but required)
		30*time.Second, // monitorInterval
		1*time.Minute,  // probabilisticInterval
	)
	times.StartRealtimeSync(ctx, 30*time.Second)

	includeTracers, err := tracertypes.Parse("all")
	if err != nil {
		return fmt.Errorf("failed to parse tracers: %w", err)
	}

	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter:          rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		SamplesPerSecond:       1,
		KernelVersionCheck:     true,
		ProbabilisticThreshold: tracer.ProbabilisticThresholdMax,
		CrashTracing:           true,
		IncludeEnvVars: libpf.Set[string]{
			"DD_SERVICE": {},
			"DD_ENV":     {},
			"DD_VERSION": {},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to load eBPF tracer: %w", err)
	}
	defer trc.Close()

	if err := rep.Start(ctx); err != nil {
		return fmt.Errorf("failed to start reporter: %w", err)
	}

	trc.StartPIDEventProcessor(ctx)

	// AttachTracer enables process discovery for new processes started after
	// oomtrace itself. Without it, the profiler only knows about processes
	// that were running at startup, and OOM traces for unknown processes are
	// dropped. A low sample rate is sufficient for discovery purposes.
	if err := trc.AttachTracer(); err != nil {
		return fmt.Errorf("failed to attach tracer: %w", err)
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("failed to attach sched monitor: %w", err)
	}

	if err := trc.StartCrashTracing(); err != nil {
		return fmt.Errorf("failed to start crash tracing: %w", err)
	}

	traceCh := make(chan *libpf.EbpfTrace)
	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %w", err)
	}

	for {
		select {
		case trace := <-traceCh:
			if trace != nil {
				trc.HandleTrace(trace)
			}
		case <-trc.Done():
			return fmt.Errorf("tracer stopped unexpectedly")
		case <-ctx.Done():
			return nil
		}
	}
}
