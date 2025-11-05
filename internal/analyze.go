package internal

import (
	"log/slog"
	"os"
	"time"

	"github.com/google/gopacket"
)

type AnalysisConfiguration struct {
	PacketRateThreshold float64
	IPRateThreshold     float64

	Window      time.Duration
	savePackets int // number of packets to save, 0 means no packets are saved
	eventFile   *os.File
	pcapFile    string // pcapFile is a string because we make a new pcap for each analysis
	logger      *slog.Logger

	context AnalysisContext
}

type AnalysisContext struct {
	// instance configuration
	srcIP            string
	c2IP             string
	sampleID         string   // unique identifier to match behavior to a malware sample
	uninterestingIPs []string // List of IP addresses that are not interesting for analysis
}

type BehaviorClass string // Classification of the behavior in a particular window

const (
	Attack BehaviorClass = "attack"
	Scan   BehaviorClass = "scanning"
	Idle   BehaviorClass = ""
)

type Behavior struct {
	Classification BehaviorClass
	Timestamp      time.Time

	PacketRate      float64
	PacketThreshold float64
	IPRate          float64
	IPRateThreshold float64

	SrcIP  *string
	DstIPs *[]string
	C2IP   *string
}

func NewAnalysisConfiguration(
	srcIP string,
	c2IP string,
	filterIPs []string,
	window time.Duration,
	filePath string,
	PacketThreshold float64,
	IPThreshold float64,
	level slog.Level,
	sampleID string,
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

	if window <= 0 {
		panic("window duration must be greater than zero")
	}

	return &AnalysisConfiguration{
		logger:              logger,
		eventFile:           file,
		PacketRateThreshold: PacketThreshold,
		IPRateThreshold:     IPThreshold,
		Window:              window,
		context: AnalysisContext{
			srcIP:            srcIP,
			c2IP:             c2IP,
			sampleID:         sampleID,
			uninterestingIPs: filterIPs,
		},
	}
}

func (config *AnalysisConfiguration) Close() error {
	if config == nil || config.eventFile == nil {
		return nil
	}
	err := config.eventFile.Close()
	config.eventFile = nil
	return err
}

// ProcessWindow processes a window of packets and logs the observed behavior.
// It detects anomalies based on the configured thresholds.
func (config *AnalysisConfiguration) ProcessWindow(
	previousBatch []gopacket.Packet,
	batch []gopacket.Packet,
	windowStart time.Time,
) {
	filteredBatch, dstIPs := filterIPsBatch(batch, &config.context.uninterestingIPs)
	_, previousDstIPs := filterIPsBatch(previousBatch, &config.context.uninterestingIPs)

	packetRate := calculatePacketRate(&filteredBatch, config.Window)
	ipRate := calculateIPRate(&previousDstIPs, &dstIPs, config.Window)

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

	behavior := config.classifyBehavior(packetRate, ipRate, &dstIPs, eventTime)

	switch behavior.Classification {
	case Idle:
		break
	case Attack:
		config.logger.Info(
			"Detected an attack",
			"type", "event",
			"behavior", behavior,
		)
		WritePackets(config.pcapFile, filteredBatch)
	case Scan:
		config.logger.Info(
			"Detected a scan",
			"type", "event",
			"behavior", behavior,
		)
	default:
		break
	}
}

func (config *AnalysisConfiguration) classifyBehavior(
	packetRate float64,
	newIPRate float64,
	destinationIPs *[]string,
	eventTime time.Time,
) Behavior {
	// found an anomalous activity
	if packetRate > config.PacketRateThreshold {
		config.logger.Debug(
			"Detected high packet rate",
			"packetRate", packetRate,
			"threshold", config.PacketRateThreshold,
			"eventTime", eventTime,
		)

		// detected a scan
		if newIPRate > config.IPRateThreshold {
			config.logger.Debug(
				"Detected high new IP rate",
				"newIPRate", newIPRate,
				"threshold", config.IPRateThreshold,
				"eventTime", eventTime,
			)

			return Behavior{
				Classification:  Scan,
				Timestamp:       eventTime,
				PacketRate:      packetRate,
				PacketThreshold: config.PacketRateThreshold,
				IPRate:          newIPRate,
				IPRateThreshold: config.IPRateThreshold,
				SrcIP:           &config.context.srcIP,
				DstIPs:          destinationIPs,
				C2IP:            &config.context.c2IP,
			}
		} else {
			// detected an attack
			return Behavior{
				Classification:  Attack,
				Timestamp:       eventTime,
				PacketRate:      packetRate,
				PacketThreshold: config.PacketRateThreshold,
				IPRate:          newIPRate,
				IPRateThreshold: config.IPRateThreshold,
				SrcIP:           &config.context.srcIP,
				DstIPs:          destinationIPs,
				C2IP:            &config.context.c2IP,
			}
		}
	}
	return Behavior{
		Classification:  Idle,
		Timestamp:       eventTime,
		PacketRate:      packetRate,
		PacketThreshold: config.PacketRateThreshold,
		IPRate:          newIPRate,
		IPRateThreshold: config.IPRateThreshold,
		SrcIP:           &config.context.srcIP,
		DstIPs:          destinationIPs,
		C2IP:            &config.context.c2IP,
	}
}

// filterIPsBatch filters a batch of packets based on a given IP filter function
// and the destination IP and returns the filtered batch as well as the
// destination IPs.
func filterIPsBatch(batch []gopacket.Packet, filterIPs *[]string) ([]gopacket.Packet, []string) {
	filteredBatch := make([]gopacket.Packet, 0, len(batch))
	dstIPs := make([]string, 0, len(batch))
	seen := make(map[string]struct{}, len(batch))

	var ignore map[string]struct{}
	if filterIPs != nil && len(*filterIPs) > 0 {
		ignore = make(map[string]struct{}, len(*filterIPs))
		for _, ip := range *filterIPs {
			if ip == "" {
				continue
			}
			ignore[ip] = struct{}{}
		}
	}

	for _, packet := range batch {
		if packet == nil {
			continue
		}
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}
		dst := networkLayer.NetworkFlow().Dst().String()

		if _, skip := ignore[dst]; skip {
			continue
		}

		filteredBatch = append(filteredBatch, packet)
		if _, ok := seen[dst]; !ok {
			dstIPs = append(dstIPs, dst)
			seen[dst] = struct{}{}
		}
	}

	return filteredBatch, dstIPs
}

// CalculatePacketRate calculates the packet rate of a given slice of packets,
// normalized by the configured window duration.
func calculatePacketRate(pkts *[]gopacket.Packet, window time.Duration) float64 {
	if pkts == nil || len(*pkts) == 0 {
		return 0.0
	}

	return float64(len(*pkts)) / window.Seconds()
}

// calculateIPRate returns the count of destination IPs in the current window that were
// not seen in the previous window.
func calculateIPRate(
	previousIPs *[]string,
	currentIPs *[]string,
	window time.Duration,
) float64 {
	if currentIPs == nil || len(*currentIPs) == 0 {
		return 0.0
	}

	var seen map[string]struct{}
	if previousIPs != nil && len(*previousIPs) > 0 {
		seen = make(map[string]struct{}, len(*previousIPs))
		for _, ip := range *previousIPs {
			if ip == "" {
				continue
			}
			seen[ip] = struct{}{}
		}
	}

	newCount := 0
	for _, ip := range *currentIPs {
		if ip == "" {
			continue
		}
		if seen != nil {
			if _, exists := seen[ip]; exists {
				continue
			}
		}
		newCount++
	}

	return float64(newCount) / window.Seconds()
}
