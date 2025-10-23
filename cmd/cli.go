package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"

	"cochaviz/net_analysis/internal"
)

const (
	defaultOutputDir          = "."
	defaultWindowSizeS        = 30
	defaultPacketRateThresh   = 120.0
	defaultUniqueIPRateThresh = 10.0
)

var RootCmd = &cobra.Command{
	Use:   "net_analysis <input> [output_dir] [window_size]",
	Short: "Analyze network traffic from a pcap file or live interface.",
	Args:  cobra.RangeArgs(1, 3),
	RunE:  executeAnalysis,
}

func executeAnalysis(cmd *cobra.Command, args []string) error {
	input := args[0]

	outputDir := defaultOutputDir
	if len(args) >= 2 && args[1] != "" {
		outputDir = args[1]
	}
	if err := ensureOutputDir(outputDir); err != nil {
		return err
	}

	windowSize := defaultWindowSizeS
	if len(args) == 3 {
		parsed, err := strconv.Atoi(args[2])
		if err != nil || parsed <= 0 {
			return fmt.Errorf("window_size must be a positive integer number of seconds: %w", err)
		}
		windowSize = parsed
	}

	handle, err := resolveHandle(input)
	if err != nil {
		return err
	}

	config := internal.NewAnalysisConfiguration(
		"", // TODO: surface configurable src IP once available.
		time.Duration(windowSize)*time.Second,
		"", // direct logs to stdout for now.
		allowAllEndpoints,
		defaultPacketRateThresh,
		defaultUniqueIPRateThresh,
		slog.LevelInfo,
	)

	if err := internal.CaptureLoop(handle, config); err != nil {
		return fmt.Errorf("capture loop failed: %w", err)
	}

	cmd.Printf("Analysis complete. Output directory: %s\n", filepath.Clean(outputDir))
	return nil
}

func resolveHandle(input string) (*pcap.Handle, error) {
	isPCAP := strings.HasSuffix(strings.ToLower(input), ".pcap")
	if isPCAP {
		return HandleFromFile(input)
	}

	info, err := os.Stat(input)
	if err == nil {
		if info.IsDir() {
			return nil, fmt.Errorf("input %q is a directory; expected file or interface", input)
		}
		return HandleFromFile(input)
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("unable to inspect %q: %w", input, err)
	}

	return HandleFromInterface(input)
}

func allowAllEndpoints(_ *gopacket.Endpoint) bool {
	return true
}

func ensureOutputDir(path string) error {
	if path == "" {
		path = defaultOutputDir
	}

	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output path %q is not a directory", path)
		}
		return nil
	}

	if errors.Is(err, fs.ErrNotExist) {
		// Create the directory tree so subsequent steps can use it.
		if mkErr := os.MkdirAll(path, 0o755); mkErr != nil {
			return fmt.Errorf("unable to create output directory %q: %w", path, mkErr)
		}
		return nil
	}

	return fmt.Errorf("unable to access output directory %q: %w", path, err)
}
