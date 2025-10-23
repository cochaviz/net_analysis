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
	logFile   *os.File
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
	var file *os.File

	if filePath == "" {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	} else {
		var err error
		file, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		logger = slog.New(slog.NewJSONHandler(file, &slog.HandlerOptions{Level: level}))
	}

	return &AnalysisConfiguration{
		srcIP:               srcIP,
		logger:              logger,
		logFile:             file,
		filterIPs:           composeEndpointFilter(srcIP, filterIPs),
		PacketRateThreshold: PacketThreshold,
		IPRateThreshold:     IPThreshold,
		Window:              window,
	}
}

func (config *AnalysisConfiguration) Close() error {
	if config == nil || config.logFile == nil {
		return nil
	}
	err := config.logFile.Close()
	config.logFile = nil
	return err
}

func composeEndpointFilter(src string, base func(*gopacket.Endpoint) bool) func(*gopacket.Endpoint) bool {
	return func(ep *gopacket.Endpoint) bool {
		if ep == nil {
			return false
		}
		if ep.String() == src {
			return false
		}
		if base == nil {
			return true
		}
		return base(ep)
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
	windowStart time.Time,
) {
	filteredBatch, dstIPs := filterIPsBatch(batch, config.filterIPs)
	filteredPreviousBatch, _ := filterIPsBatch(previousBatch, config.filterIPs)

	packetRate := calculatePacketRate(&filteredBatch)
	ipRate := calculateIPRate(&filteredPreviousBatch, &filteredBatch)

	eventTime := windowStart
	if eventTime.IsZero() {
		if len(filteredBatch) > 0 {
			if md := filteredBatch[0].Metadata(); md != nil {
				eventTime = md.Timestamp
			}
		}
	}
	if eventTime.IsZero() && len(batch) > 0 {
		if md := batch[0].Metadata(); md != nil {
			eventTime = md.Timestamp
		}
	}
	if eventTime.IsZero() {
		eventTime = time.Now()
	}

	config.logBehavior(packetRate, ipRate, &dstIPs, eventTime)
}

func (config *AnalysisConfiguration) logBehavior(
	packetRate float64,
	newIPRate float64,
	destinationIPs *[]string,
	eventTime time.Time,
) bool {
	// found an anomalous activity
	if packetRate > config.PacketRateThreshold {
		config.logger.Debug(
			"Packet rate exceeded threshold",
			"type", "event",
			"timestamp", eventTime,
			"packetRate", packetRate,
			"threshold", config.PacketRateThreshold,
			"sourceIP", config.srcIP,
		)

		// detected a scan
		if newIPRate > config.IPRateThreshold {
			config.logger.Info(
				"Detected a scan",
				"type", "alert",
				"timestamp", eventTime,
				"ipRate", newIPRate,
				"threshold", config.IPRateThreshold,
				"sourceIP", config.srcIP,
				"destinationIPs", destinationIPs,
			)
		} else {
			// detected an attack
			config.logger.Info(
				"Attack detected",
				"type", "alert",
				"timestamp", eventTime,
				"packetRate", packetRate,
				"threshold", config.PacketRateThreshold,
				"sourceIP", config.srcIP,
				"destinationIPs", destinationIPs,
			)
		}
	} else {
		config.logger.Debug(
			"No anomaly within window",
			"type", "event",
			"timestamp", eventTime,
			"packetRate", packetRate,
			"threshold", config.PacketRateThreshold,
			"sourceIP", config.srcIP,
		)
	}
	return false
}

// filterIPsBatch filters a batch of packets based on a given IP filter function
// and the destination IP and returns the filtered batch as well as the
// destination IPs.
func filterIPsBatch(batch []gopacket.Packet, filterIPs func(*gopacket.Endpoint) bool) ([]gopacket.Packet, []string) {
	var filteredBatch []gopacket.Packet
	dstIPs := make([]string, 0, len(batch))
	seen := make(map[string]struct{}, len(batch))

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
			ipStr := dstIP.String()
			if _, ok := seen[ipStr]; !ok {
				seen[ipStr] = struct{}{}
				dstIPs = append(dstIPs, ipStr)
			}
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
