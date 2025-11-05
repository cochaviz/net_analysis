package internal

import (
	"log/slog"
	"os"
	"time"

	"github.com/google/gopacket"
)

// == Analysis

type AnalysisConfiguration struct {
	// configuration
	PacketRateThreshold float64
	IPRateThreshold     float64
	Window              time.Duration
	savePackets         int    // number of packets to save, 0 means no packets are saved
	pcapFile            string // pcapFile is a string because we make a new pcap for each analysis
	heartbeat           bool   // include heartbeat packets in analysis
	hostCount           map[string]int

	// instance references
	eventFile *os.File
	logger    *slog.Logger

	// static context for logging
	context AnalysisContext
}

type AnalysisContext struct {
	// instance configuration
	srcIP            string
	c2IP             string
	sampleID         string   // unique identifier to match behavior to a malware sample
	uninterestingIPs []string // List of IP addresses that are not interesting for analysis
}

func NewAnalysisConfiguration(
	srcIP string,
	c2IP string,
	filterIPs []string,
	heartbeat bool,
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
		heartbeat:           heartbeat,
		context: AnalysisContext{
			srcIP:            srcIP,
			c2IP:             c2IP,
			sampleID:         sampleID,
			uninterestingIPs: filterIPs,
		},
	}
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

	eventTime := getEventTime(windowStart, &batch, &filteredBatch)

	behavior := config.classifyGlobalBehavior(packetRate, ipRate, &dstIPs, eventTime)

	config.logBehavior(behavior, filteredBatch)
}

func (config *AnalysisConfiguration) logBehavior(
	behavior *Behavior,
	packets []gopacket.Packet,
) {
	if behavior == nil {
		return
	}

	switch behavior.Classification {
	case Idle:
		if config.heartbeat {
			config.logger.Info(
				"Idling",
				"type", "heartbeat",
				"behavior", behavior,
			)
		}
	case Attack:
		config.logger.Info(
			"Detected an attack",
			"type", "event",
			"behavior", behavior,
		)
		WritePackets(config.pcapFile, packets)
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

func (config *AnalysisConfiguration) classifyLocalBehavior(
	packetRate float64,
	destinationIP string,
	eventTime time.Time,
) *Behavior {
	if packetRate > config.PacketRateThreshold {
		return &Behavior{
			Classification:  Attack,
			Scope:           Local,
			Timestamp:       eventTime,
			PacketRate:      packetRate,
			PacketThreshold: config.PacketRateThreshold,
			IPRate:          0,
			IPRateThreshold: 0,
			DstIP:           &destinationIP,
			SrcIP:           &config.context.srcIP,
		}
	}
	return nil
}

func (config *AnalysisConfiguration) classifyGlobalBehavior(
	globalPacketRate float64,
	newIPRate float64,
	destinationIPs *[]string,
	eventTime time.Time,
) *Behavior {
	// found an anomalous activity
	if globalPacketRate > config.PacketRateThreshold {
		config.logger.Debug(
			"Detected global high packet rate",
			"scope", Global,
			"eventTime", eventTime,
			"packetRate", globalPacketRate,
			"threshold", config.PacketRateThreshold,
		)

		// detected a scan
		if newIPRate > config.IPRateThreshold {
			config.logger.Debug(
				"Detected high new IP rate",
				"scope", Global,
				"eventTime", eventTime,
				"newIPRate", newIPRate,
				"threshold", config.IPRateThreshold,
			)

			return &Behavior{
				Classification:  Scan,
				Scope:           Global,
				Timestamp:       eventTime,
				PacketRate:      globalPacketRate,
				PacketThreshold: config.PacketRateThreshold,
				IPRate:          newIPRate,
				IPRateThreshold: config.IPRateThreshold,
				SrcIP:           &config.context.srcIP,
				DstIPs:          destinationIPs,
				C2IP:            &config.context.c2IP,
				SampleID:        config.context.sampleID,
			}
		}
	}

	return &Behavior{
		Classification:  Idle,
		Scope:           Global,
		Timestamp:       eventTime,
		PacketRate:      globalPacketRate,
		PacketThreshold: config.PacketRateThreshold,
		IPRate:          newIPRate,
		IPRateThreshold: config.IPRateThreshold,
		SrcIP:           &config.context.srcIP,
		DstIPs:          destinationIPs,
		C2IP:            &config.context.c2IP,
		SampleID:        config.context.sampleID,
	}
}

// == Behavior

type BehaviorScope string

const (
	Global BehaviorScope = "global"
	Local  BehaviorScope = "local"
)

type BehaviorClass string // Classification of the behavior in a particular window

const (
	Attack BehaviorClass = "attack"
	Scan   BehaviorClass = "scanning"
	Idle   BehaviorClass = ""
)

type Behavior struct {
	Classification BehaviorClass `json:"classification"`
	Scope          BehaviorScope `json:"scope"`      // Indicates the scope of the behavior (global/local)
	Timestamp      time.Time     `json:"@timestamp"` // @timestamp to comply with Elastic

	PacketRate      float64 `json:"packet_rate"`
	PacketThreshold float64 `json:"packet_threshold"`
	IPRate          float64 `json:"ip_rate"`
	IPRateThreshold float64 `json:"ip_rate_threshold"`

	SampleID string  `json:"sample_id"`
	SrcIP    *string `json:"src_ip"`
	C2IP     *string `json:"c2_ip"`

	// Destination IP/s depending on the scope
	DstIPs *[]string `json:"dst_ips"`
	DstIP  *string   `json:"dst_ip"`
}

func (config *AnalysisConfiguration) Close() error {
	if config == nil || config.eventFile == nil {
		return nil
	}
	err := config.eventFile.Close()
	config.eventFile = nil
	return err
}

// == Helper Functions

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

// getEventTime returns the timestamp of the start of the window, or of the
// first packet in the batch or filtered batch, or the current time if no
// packets are available.
func getEventTime(
	windowStart time.Time,
	batch *[]gopacket.Packet,
	filteredBatch *[]gopacket.Packet,
) time.Time {
	eventTime := windowStart

	if eventTime.IsZero() {
		if filteredBatch != nil && len(*filteredBatch) > 0 {
			if md := (*filteredBatch)[0].Metadata(); md != nil {
				eventTime = md.Timestamp
			}
		} else if batch != nil && len(*batch) > 0 {
			if md := (*batch)[0].Metadata(); md != nil {
				eventTime = md.Timestamp
			}
		} else {
			eventTime = time.Now()
		}
	}

	return eventTime
}
