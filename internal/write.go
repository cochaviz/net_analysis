package internal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var fileComponentSanitizer = strings.NewReplacer(
	"/", "-",
	"\\", "-",
	":", "-",
	" ", "_",
	"\t", "_",
)

func sanitizeFileComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return fileComponentSanitizer.Replace(value)
}

func BuildCapturePath(baseDir string, behavior *Behavior) (string, error) {
	if behavior == nil {
		return "", errors.New("behavior is nil")
	}

	ts := behavior.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	classComponent := sanitizeFileComponent(string(behavior.Classification))
	if classComponent == "" {
		classComponent = "behavior"
	}

	hostComponent := sanitizeFileComponent("global")
	if behavior.DstIP != nil && *behavior.DstIP != "" {
		hostComponent = sanitizeFileComponent(*behavior.DstIP)
	}

	sampleComponent := sanitizeFileComponent(behavior.SampleID)
	timeComponent := ts.UTC().Format("20060102T150405Z")

	parts := []string{classComponent}
	if sampleComponent != "" {
		parts = append(parts, sampleComponent)
	}
	if hostComponent != "" {
		parts = append(parts, hostComponent)
	}
	parts = append(parts, timeComponent)

	filename := strings.Join(parts, "_") + ".pcap"

	root := baseDir
	if root == "" {
		root = filepath.Join(".", "captures")
	}
	root = filepath.Clean(root)

	return filepath.Join(root, filename), nil
}

func WritePackets(filename string, packets []gopacket.Packet, linkType layers.LinkType) error {
	if len(packets) == 0 || filename == "" {
		return nil
	}

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)

	var snapLen uint32
	for _, packet := range packets {
		if packet == nil {
			continue
		}
		if md := packet.Metadata(); md != nil && md.CaptureInfo.CaptureLength > 0 {
			snapLen = uint32(md.CaptureInfo.CaptureLength)
			break
		}
		if data := packet.Data(); len(data) > 0 {
			snapLen = uint32(len(data))
			break
		}
	}
	if snapLen == 0 {
		snapLen = 65535
	}
	if linkType == 0 {
		linkType = layers.LinkTypeEthernet
	}

	if err := writer.WriteFileHeader(snapLen, linkType); err != nil {
		return err
	}

	for _, packet := range packets {
		if packet == nil {
			continue
		}

		data := packet.Data()
		if len(data) == 0 {
			continue
		}

		var ci gopacket.CaptureInfo
		if md := packet.Metadata(); md != nil {
			ci = md.CaptureInfo
		}
		if ci.CaptureLength == 0 {
			ci.CaptureLength = len(data)
		}
		if ci.Length == 0 {
			ci.Length = len(data)
		}
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Now()
		}

		if err := writer.WritePacket(ci, data); err != nil {
			return err
		}
	}

	return nil
}

func WriteBehaviorCapture(
	baseDir string,
	behavior *Behavior,
	packets []gopacket.Packet,
	linkType layers.LinkType,
) (string, error) {
	if behavior == nil || len(packets) == 0 {
		return "", nil
	}

	path, err := BuildCapturePath(baseDir, behavior)
	if err != nil {
		return "", err
	}

	if err := WritePackets(path, packets, linkType); err != nil {
		return "", err
	}
	return path, nil
}

func WriteToFile(filename string, content []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(content)
	if err != nil {
		return err
	}
	return nil
}
