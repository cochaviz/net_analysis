package internal

import (
	"log/slog"
	"os"
	"time"

	"github.com/google/gopacket"
)

type AnalysisConfiguration struct {
	// threshold configuration
	PacketRateThreshold float64
	IPRateThreshold     float64
	Window              time.Duration

	// instance configuration
	srcIP     string
	logger    *slog.Logger
	filterIPs func(*gopacket.Endpoint) bool
}

func NewAnalysisConfiguration(
	srcIP string,
	window time.Duration,
	filePath string,
	filterIPs func(*gopacket.Endpoint) bool,
	PacketThreshold float64,
	IPThreshold float64,
	level slog.Level,
) *AnalysisConfiguration {
	var logger *slog.Logger

	if filePath == "" {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	} else {
		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		logger = slog.New(slog.NewJSONHandler(file, &slog.HandlerOptions{Level: level}))
	}

	return &AnalysisConfiguration{
		srcIP:               srcIP,
		logger:              logger,
		filterIPs:           filterIPs,
		PacketRateThreshold: PacketThreshold,
		IPRateThreshold:     IPThreshold,
		Window:              window,
	}
}

// TODO: maybe later!
// type BehaviorLog struct {
// 	message        string
// 	packetRate     float64
// 	threshold      float64
// 	sourceIP       string
// 	destinationIPs []string
// }

// ProcessWindow processes a window of packets and logs the observed behavior.
// It detects anomalies based on the configured thresholds.
func (config *AnalysisConfiguration) ProcessWindow(
	previousBatch []gopacket.Packet,
	batch []gopacket.Packet,
) {
	filteredBatch, dstIPs := filterIPsBatch(batch, config.filterIPs)
	filteredPreviousBatch, _ := filterIPsBatch(previousBatch, config.filterIPs)

	packetRate := calculatePacketRate(&filteredBatch)
	ipRate := calculateIPRate(&filteredPreviousBatch, &filteredBatch)

	config.logBehavior(packetRate, ipRate, &dstIPs)
}

func (config *AnalysisConfiguration) logBehavior(
	packetRate float64,
	newIPRate float64,
	destinationIPs *[]string,
) bool {
	// found an anomalous activity
	if packetRate > config.PacketRateThreshold {
		config.logger.Debug(
			"Packet rate exceeded threshold",
			"packetRate", packetRate,
			"threshold", config.PacketRateThreshold,
			"sourceIP", config.srcIP,
		)

		// detected a scan
		if newIPRate > config.IPRateThreshold {
			config.logger.Info(
				"Detected a scan",
				"ipRate", newIPRate,
				"threshold", config.IPRateThreshold,
				"sourceIP", config.srcIP,
				"destinationIPs", destinationIPs,
			)
		} else {
			// detected an attack
			config.logger.Info(
				"Attack detected",
				"packetRate", packetRate,
				"threshold", config.PacketRateThreshold,
				"sourceIP", config.srcIP,
				"destinationIPs", destinationIPs,
			)
		}
	}
	return false
}

// filterIPsBatch filters a batch of packets based on a given IP filter function
// and the destination IP and returns the filtered batch as well as the
// destination IPs.
func filterIPsBatch(batch []gopacket.Packet, filterIPs func(*gopacket.Endpoint) bool) ([]gopacket.Packet, []string) {
	var filteredBatch []gopacket.Packet
	var dstIPs []string

	for _, packet := range batch {
		if packet == nil {
			continue
		}

		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			continue
		}

		dstIP := packet.NetworkLayer().NetworkFlow().Dst()

		if filterIPs(&dstIP) {
			filteredBatch = append(filteredBatch, packet)
			dstIPs = append(dstIPs, dstIP.String())
		}
	}

	return filteredBatch, dstIPs
}

// CalculatePacketRate calculates the packet rate of a given slice of packets.
func calculatePacketRate(pkts *[]gopacket.Packet) float64 {
	if pkts == nil || len(*pkts) == 0 {
		return 0.0
	}

	startTime := (*pkts)[0].Metadata().Timestamp
	endTime := (*pkts)[len(*pkts)-1].Metadata().Timestamp

	duration := endTime.Sub(startTime).Seconds()
	rate := float64(len(*pkts)) / duration

	return rate
}

func calculateIPRate(previousBatch *[]gopacket.Packet, batch *[]gopacket.Packet) float64 {
	if batch == nil || len(*batch) == 0 {
		return 0.0
	}

	startTime := (*batch)[0].Metadata().Timestamp
	endTime := (*batch)[len(*batch)-1].Metadata().Timestamp

	duration := endTime.Sub(startTime).Seconds()
	rate := float64(len(*batch)) / duration

	return rate
}
