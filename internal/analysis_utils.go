package internal

import (
	"time"

	"github.com/google/gopacket"
)

type MaxHostsReached struct{}

func (e *MaxHostsReached) Error() string {
	return "maximum number of hosts reached"
}

type packetRing struct {
	max   int
	items []gopacket.Packet
}

func newPacketRing(max int) *packetRing {
	if max <= 0 {
		max = 1
	}
	return &packetRing{
		max:   max,
		items: make([]gopacket.Packet, 0, max),
	}
}

func (r *packetRing) add(packet gopacket.Packet) {
	if r == nil || r.max <= 0 {
		return
	}
	if len(r.items) < r.max {
		r.items = append(r.items, packet)
		return
	}
	copy(r.items, r.items[1:])
	r.items[len(r.items)-1] = packet
}

func (r *packetRing) snapshot() []gopacket.Packet {
	if r == nil || len(r.items) == 0 {
		return nil
	}
	out := make([]gopacket.Packet, len(r.items))
	copy(out, r.items)
	return out
}

func mergeHostCounts(acc map[string]int, batch map[string]int) (map[string]int, int) {
	if len(batch) == 0 {
		return acc, 0
	}

	if acc == nil {
		acc = make(map[string]int, len(batch))
	}

	newHosts := 0

	for host, count := range batch {
		if count == 0 {
			continue
		}
		if _, exists := acc[host]; !exists {
			newHosts++
		}
		acc[host] += count
	}

	return acc, newHosts
}

// countPacketsByHost tallies packets overall and per destination host.
func countPacketsByHost(
	pkts *[]gopacket.Packet,
	excludeIPs *[]string,
	maxHosts int,
) (int, map[string]int, error) {
	if pkts == nil || len(*pkts) == 0 {
		return 0, nil, nil
	}

	hostCounts := make(map[string]int, maxHosts)
	total := 0

	var exclude map[string]struct{}
	if excludeIPs != nil && len(*excludeIPs) > 0 {
		exclude = make(map[string]struct{}, len(*excludeIPs))
		for _, ip := range *excludeIPs {
			if ip == "" {
				continue
			}
			exclude[ip] = struct{}{}
		}
	}

	for _, packet := range *pkts {
		if packet == nil {
			continue
		}
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		dst := networkLayer.NetworkFlow().Dst().String()

		if _, skip := exclude[dst]; skip {
			continue
		}

		total++

		if len(hostCounts) < maxHosts || hostCounts[dst] > 0 {
			hostCounts[dst]++
		} else {
			return total, hostCounts, &MaxHostsReached{}
		}
	}

	return total, hostCounts, nil
}

// getEventTime returns the timestamp of the start of the window, or of the
// first packet in the batch or filtered batch, or the current time if no
// packets are available.
func getEventTime(
	windowStart time.Time,
	batch *[]gopacket.Packet,
) time.Time {
	eventTime := windowStart

	if eventTime.IsZero() {
		if batch != nil && len(*batch) > 0 {
			if md := (*batch)[0].Metadata(); md != nil {
				eventTime = md.Timestamp
			}
		} else {
			eventTime = time.Now()
		}
	}

	return eventTime
}
