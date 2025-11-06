package internal

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// == Analysis

type MaxHostsReached struct{}

func (e MaxHostsReached) Error() string {
	return "maximum number of hosts reached"
}

type AnalysisConfiguration struct {
	// configuration
	PacketRateThreshold float64
	IPRateThreshold     float64
	Window              time.Duration
	maxHosts            map[string]int // maximum number of hosts to analyze

	// extra logging options
	heartbeat   bool // include heartbeat packets in analysis
	savePackets int  // number of packets to save, 0 means no packets are saved
	captureDir  string
	linkType    layers.LinkType

	// instance references
	eventFile *os.File
	logger    *slog.Logger

	result    batchResult
	buffers   map[string]*packetRing
	ignoredIP map[string]struct{}

	// static context for logging
	context AnalysisContext
}

type batchResult struct {
	windowStart       time.Time
	hostPacketCounts  map[string]int
	globalPacketCount int
	globalNewIPCount  int
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
	savePackets int,
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

	// source and C2 IPs should be excluded from analysis
	filterIPs = append(filterIPs, srcIP, c2IP)

	ignored := make(map[string]struct{}, len(filterIPs))
	for _, ip := range filterIPs {
		if ip == "" {
			continue
		}
		ignored[ip] = struct{}{}
	}

	var buffers map[string]*packetRing
	if savePackets > 0 {
		buffers = make(map[string]*packetRing)
	}

	baseDir := "."
	if filePath != "" {
		baseDir = filepath.Dir(filePath)
	}
	captureDir := filepath.Join(baseDir, "captures")

	return &AnalysisConfiguration{
		logger:              logger,
		eventFile:           file,
		PacketRateThreshold: PacketThreshold,
		IPRateThreshold:     IPThreshold,
		Window:              window,
		heartbeat:           heartbeat,
		savePackets:         savePackets,
		captureDir:          captureDir,
		buffers:             buffers,
		ignoredIP:           ignored,
		context: AnalysisContext{
			srcIP:            srcIP,
			c2IP:             c2IP,
			sampleID:         sampleID,
			uninterestingIPs: filterIPs,
		},
	}
}

// ProcessBatch processes a (subset) of a window of packets and saves
// intermediate results.
func (config *AnalysisConfiguration) ProcessBatch(
	_ []gopacket.Packet,
	batch []gopacket.Packet,
	windowStart time.Time,
) {
	if len(batch) == 0 {
		return
	}
	if config.result.windowStart.IsZero() {
		config.result.windowStart = windowStart
	}

	if config.savePackets > 0 {
		config.captureRecentPackets(batch)
	}

	globalPacketCount, localPacketCounts, err := countPacketsByHost(&batch, &config.context.uninterestingIPs, 512)
	if err != nil {
		config.logger.Error("Error counting packet totals", "error", err)
	}

	// Save intermediate results; normalization happens when the window flushes.
	config.result.globalPacketCount += globalPacketCount
	var newHostCount int
	config.result.hostPacketCounts, newHostCount = mergeHostCounts(
		config.result.hostPacketCounts,
		localPacketCounts,
	)
	config.result.globalNewIPCount += newHostCount
}

func (config *AnalysisConfiguration) captureRecentPackets(batch []gopacket.Packet) {
	if config.savePackets <= 0 || len(batch) == 0 || config.buffers == nil {
		return
	}

	for _, packet := range batch {
		if packet == nil {
			continue
		}
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		var hosts []string
		src := networkLayer.NetworkFlow().Src().String()
		if src != "" {
			hosts = append(hosts, src)
		}
		dst := networkLayer.NetworkFlow().Dst().String()
		if dst != "" {
			hosts = append(hosts, dst)
		}

		if len(hosts) == 0 {
			continue
		}

		seen := make(map[string]struct{}, len(hosts))
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			config.appendPacketForHost(host, packet)
		}
	}
}

func (config *AnalysisConfiguration) appendPacketForHost(host string, packet gopacket.Packet) {
	if !config.shouldTrackHost(host) {
		return
	}

	buf, ok := config.buffers[host]
	if !ok {
		buf = newPacketRing(config.savePackets)
		config.buffers[host] = buf
	}
	buf.add(packet)
}

func (config *AnalysisConfiguration) shouldTrackHost(host string) bool {
	if host == "" || config.savePackets <= 0 {
		return false
	}
	if config.ignoredIP != nil {
		if _, skip := config.ignoredIP[host]; skip {
			return false
		}
	}
	return true
}

func (config *AnalysisConfiguration) snapshotHostPackets(host string) []gopacket.Packet {
	if config.buffers == nil {
		return nil
	}
	buf, ok := config.buffers[host]
	if !ok || buf == nil {
		return nil
	}
	return buf.snapshot()
}

func (config *AnalysisConfiguration) flushResults() {
	if config.result.globalPacketCount == 0 && len(config.result.hostPacketCounts) == 0 {
		return
	}
	if config.result.windowStart.IsZero() {
		return
	}
	windowDuration := config.Window
	if windowDuration <= 0 {
		config.logger.Warn(
			"Unable to normalize rates due to non-positive duration",
			"window", config.Window,
		)
		windowDuration = time.Second
	}
	durationSeconds := windowDuration.Seconds()
	windowEnd := config.result.windowStart.Add(windowDuration)

	config.logger.Debug(
		"Flushing results",
		"windowStart", config.result.windowStart,
		"windowEnd", windowEnd,
		"windowSeconds", durationSeconds,
		"globalPacketCount", config.result.globalPacketCount,
		"hostPacketCounts", config.result.hostPacketCounts,
		"globalNewIPCount", config.result.globalNewIPCount,
	)

	// classify and log behaviors
	for host, count := range config.result.hostPacketCounts {
		packetRate := float64(count) / durationSeconds
		localBehavior := config.classifyLocalBehavior(packetRate, host, config.result.windowStart)
		var captured []gopacket.Packet
		if localBehavior != nil &&
			localBehavior.Classification == Attack &&
			localBehavior.DstIP != nil &&
			config.savePackets > 0 {
			captured = config.snapshotHostPackets(*localBehavior.DstIP)
		}
		config.logBehavior(localBehavior, captured)
	}

	globalPacketRate := float64(config.result.globalPacketCount) / durationSeconds
	globalIPRate := float64(config.result.globalNewIPCount) / durationSeconds

	globalBehavior := config.classifyGlobalBehavior(
		globalPacketRate,
		globalIPRate,
		nil,
		config.result.windowStart,
	)
	config.logBehavior(globalBehavior, nil)

	// clear results after flush
	config.result = batchResult{}
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
			args := []any{"type", "heartbeat"}
			args = append(args, behaviorLogArgs(behavior)...)
			config.logger.Info("Idling", args...)
		}
	case Attack:
		if config.savePackets > 0 {
			config.persistPackets(behavior, packets)
		}
		args := []any{"type", "event"}
		args = append(args, behaviorLogArgs(behavior)...)
		config.logger.Info("Detected an attack", args...)
	case Scan:
		args := []any{"type", "event"}
		args = append(args, behaviorLogArgs(behavior)...)
		config.logger.Info("Detected a scan", args...)
	default:
		break
	}
}

func behaviorLogArgs(behavior *Behavior) []any {
	if behavior == nil {
		return nil
	}

	var args []any

	if behavior.Classification != "" {
		args = append(args, "classification", behavior.Classification)
	}
	if behavior.Scope != "" {
		args = append(args, "scope", behavior.Scope)
	}
	if !behavior.Timestamp.IsZero() {
		args = append(args, "@timestamp", behavior.Timestamp)
	}

	if behavior.PacketRate > 0 {
		args = append(args, "packet_rate", behavior.PacketRate)
	}
	if behavior.PacketThreshold > 0 {
		args = append(args, "packet_threshold", behavior.PacketThreshold)
	}
	if behavior.IPRate > 0 {
		args = append(args, "ip_rate", behavior.IPRate)
	}
	if behavior.IPRateThreshold > 0 {
		args = append(args, "ip_rate_threshold", behavior.IPRateThreshold)
	}
	if behavior.SampleID != "" {
		args = append(args, "sample_id", behavior.SampleID)
	}
	if behavior.SrcIP != nil && *behavior.SrcIP != "" {
		args = append(args, "src_ip", *behavior.SrcIP)
	}
	if behavior.C2IP != nil && *behavior.C2IP != "" {
		args = append(args, "c2_ip", *behavior.C2IP)
	}
	if behavior.DstIP != nil && *behavior.DstIP != "" {
		args = append(args, "dst_ip", *behavior.DstIP)
	}
	if behavior.DstIPs != nil && len(*behavior.DstIPs) > 0 {
		args = append(args, "dst_ips", *behavior.DstIPs)
	}

	return args
}

func (config *AnalysisConfiguration) persistPackets(behavior *Behavior, packets []gopacket.Packet) {
	if config.savePackets <= 0 || behavior == nil {
		return
	}

	data := packets
	if len(data) == 0 && behavior.DstIP != nil {
		data = config.snapshotHostPackets(*behavior.DstIP)
	}
	if len(data) == 0 {
		return
	}

	path, err := WriteBehaviorCapture(config.captureDir, behavior, data, config.linkType)
	if err != nil {
		config.logger.Error(
			"Failed to write captured packets",
			"error", err,
		)
		return
	}
	if path != "" {
		config.logger.Debug(
			"Saved attack packet capture",
			"path", path,
			"count", len(data),
		)
	}
}

func (config *AnalysisConfiguration) classifyLocalBehavior(
	packetRate float64,
	destinationIP string,
	eventTime time.Time,
) *Behavior {
	config.logger.Debug(
		"Classifying local behavior",
		"packetRate", packetRate,
		"threshold", config.PacketRateThreshold,
		"destinationIP", destinationIP,
	)

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
			SampleID:        config.context.sampleID,
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
			return total, hostCounts, MaxHostsReached{}
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
