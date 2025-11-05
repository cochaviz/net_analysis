package internal

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type windowBatch struct {
	packets []gopacket.Packet
	start   time.Time
}

func CaptureLoop(handle *pcap.Handle, config *AnalysisConfiguration) error {
	config.logger.Debug("Starting capture loop")
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = false // safe to retain packets beyond next read
	packets := src.Packets()

	config.logger.Debug("Initialized packet source")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	catchSignals(cancel)

	process := make(chan windowBatch, 2)
	workerDone := make(chan struct{})
	go worker(config, process, workerDone)

	// Buffer for the current packet window.
	cur := make([]gopacket.Packet, 0, 4096)
	var windowStart time.Time

	config.logger.Debug(
		"Initialized time-window tracking",
		"window", config.Window,
		"bufferCapacity", cap(cur),
	)

	for {
		select {
		case <-ctx.Done():
			// flush last partial window
			if len(cur) > 0 {
				config.logger.Debug(
					"Context canceled, flushing partial batch",
					"count", len(cur),
				)
				handoff(process, &cur, windowStart)
			}
			close(process)
			<-workerDone
			return nil

		case p, ok := <-packets:
			if !ok {
				// source closed; flush and exit
				if len(cur) > 0 {
					config.logger.Debug(
						"Packet source closed, flushing partial batch",
						"count", len(cur),
					)
					handoff(process, &cur, windowStart)
				}
				close(process)
				<-workerDone
				return nil
			}

			if p == nil {
				config.logger.Debug("Skipping nil packet from source")
				continue
			}

			metadata := p.Metadata()
			var ts time.Time
			if metadata != nil {
				ts = metadata.Timestamp
			}
			if ts.IsZero() {
				ts = time.Now()
				config.logger.Debug(
					"Packet timestamp missing; using current time",
					"bufferLen", len(cur),
				)
			}

			if len(cur) == 0 {
				windowStart = ts
			} else if ts.Sub(windowStart) >= config.Window {
				config.logger.Debug(
					"Handing off packet batch due to elapsed window",
					"count", len(cur),
					"windowStart", windowStart,
					"windowEnd", ts,
				)
				handoff(process, &cur, windowStart)
				windowStart = ts
			}

			cur = append(cur, p)
			if len(cur) == cap(cur) {
				config.logger.Debug(
					"Handing off packet batch at capacity",
					"count", len(cur),
				)
				handoff(process, &cur, windowStart)
			}
		}
	}
}

func handoff(process chan<- windowBatch, cur *[]gopacket.Packet, start time.Time) {
	// Copy packets so the capture loop can safely reuse its buffer.
	batch := make([]gopacket.Packet, len(*cur))
	copy(batch, *cur)
	process <- windowBatch{packets: batch, start: start}
	*cur = (*cur)[:0]
}

func worker(config *AnalysisConfiguration, in <-chan windowBatch, done chan<- struct{}) {
	defer close(done)
	var previous windowBatch

	for batch := range in {
		config.logger.Debug(
			"Processing packet window",
			"previousCount", len(previous.packets),
			"currentCount", len(batch.packets),
		)
		config.ProcessBatch(previous.packets, batch.packets, batch.start)
		previous = batch
	}

	if len(previous.packets) > 0 {
		config.logger.Debug(
			"Flushing final packet window",
			"previousCount", len(previous.packets),
		)
		config.ProcessBatch(previous.packets, nil, previous.start)
	}
}

func catchSignals(cancel context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ch; cancel() }()
}
