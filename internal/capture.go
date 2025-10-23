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

func CaptureLoop(handle *pcap.Handle, config *AnalysisConfiguration) error {
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = false // safe to retain packets beyond next read
	packets := src.Packets()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	catchSignals(cancel)

	process := make(chan []gopacket.Packet, 2)
	go worker(config, ctx, process)

	// Current 30s window.
	cur := make([]gopacket.Packet, 0, 4096)
	ticker := time.NewTicker(config.Window)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// flush last partial window
			if len(cur) > 0 {
				handoff(process, &cur)
			}
			close(process)
			return nil

		case p, ok := <-packets:
			if !ok {
				// source closed; flush and exit
				if len(cur) > 0 {
					handoff(process, &cur)
				}
				close(process)
				return nil
			}
			cur = append(cur, p)

		case <-ticker.C:
			// exactly one handoff per tick
			if len(cur) > 0 {
				handoff(process, &cur)
			}
		}
	}
}

func handoff(process chan<- []gopacket.Packet, cur *[]gopacket.Packet) {
	process <- *cur
	*cur = (*cur)[:0]
}

func worker(config *AnalysisConfiguration, ctx context.Context, in <-chan []gopacket.Packet) {
	previousBatch := make([]gopacket.Packet, 0, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-in:
			if !ok {
				config.ProcessWindow(
					previousBatch,
					batch,
				)
				previousBatch = batch
				return
			}

		}
	}
}

func catchSignals(cancel context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ch; cancel() }()
}
