package internal

import (
	"log/slog"
	"os"
	"slices"
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
	packetRate     float64
	threshold      float64
	srcIP          *string
	dstIPs         *[]string
	c2IP           *string
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

// ProcessWindow processes a window of packets and logs the observed behavior.
// It detects anomalies based on the configured thresholds.
func (config *AnalysisConfiguration) ProcessWindow(
	previousBatch []gopacket.Packet,
	batch []gopacket.Packet,
	windowStart time.Time,
) {
	filteredBatch, dstIPs := filterIPsBatch(batch, config.filterIPs)
	_, previousDstIPs := filterIPsBatch(previousBatch, config.filterIPs)

	packetRate := calculatePacketRate(&filteredBatch)
	ipRate := calculateIPRate(
		&previousDstIPs,
		&dstIPs,
		config.Window,
	)

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
			"timestamp", eventTime,
			"behavior", behavior,
		)
		WritePackets(config.pcapFile, filteredBatch)
	case Scan:
		config.logger.Info(
			"Detected a scan",
			"type", "event",
			"timestamp", eventTime,
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
		config.logger.Info(
			"Detected high packet rate",
			"context", slog.Any("context", config.context),
		)

		// detected a scan
		if newIPRate > config.IPRateThreshold {
			return Behavior{
				Classification: Scan,
				Timestamp:      eventTime,
				packetRate:     newIPRate,
				threshold:      config.IPRateThreshold,
				srcIP:          &config.context.srcIP,
				dstIPs:         destinationIPs,
				c2IP:           &config.context.c2IP,
			}
		} else {
			// detected an attack
			return Behavior{
				Classification: Attack,
				Timestamp:      eventTime,
				packetRate:     packetRate,
				threshold:      config.PacketRateThreshold,
				srcIP:          &config.context.srcIP,
				dstIPs:         destinationIPs,
				c2IP:           &config.context.c2IP,
			}
		}
	}
	return Behavior{
		Classification: Idle,
		Timestamp:      eventTime,
		packetRate:     packetRate,
		threshold:      config.PacketRateThreshold,
		srcIP:          &config.context.srcIP,
		dstIPs:         destinationIPs,
		c2IP:           &config.context.c2IP,
	}
}

// filterIPsBatch filters a batch of packets based on a given IP filter function
// and the destination IP and returns the filtered batch as well as the
// destination IPs.
func filterIPsBatch(batch []gopacket.Packet, filterIPs *[]string) ([]gopacket.Packet, []string) {
	var filteredBatch []gopacket.Packet
	dstIPs := make([]string, 0, len(batch))
	seen := make(map[string]struct{}, len(batch))

	for _, packet := range batch {
		if packet == nil {
			continue
		}

		if filterIPs != nil {
			if _, ok := seen[packet.NetworkLayer().NetworkFlow().Dst().String()]; !ok {
				dstIPs = append(dstIPs, packet.NetworkLayer().NetworkFlow().Dst().String())
				seen[packet.NetworkLayer().NetworkFlow().Dst().String()] = struct{}{}
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

// Calculates the new IP rate. Here, new IPs are IPs that are not in the previous batch.
func calculateIPRate(
	previousIPs *[]string,
	currentIPs *[]string,
	windowSize time.Duration,
) float64 {
	if currentIPs == nil || len(*currentIPs) == 0 {
		return 0.0
	}
	numNewIPs := []string{}
	for _, ip := range *currentIPs {
		if !slices.Contains(*previousIPs, ip) {
			numNewIPs = append(numNewIPs, ip)
		}
	}
	rate := float64(len(numNewIPs)) / windowSize.Seconds()
	return rate
}
