package cmd

import (
	"github.com/google/gopacket/pcap"
)

func HandleFromFile(inputFile string) (*pcap.Handle, error) {
	handle, err := pcap.OpenOffline(inputFile)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

func HandleFromInterface(interfaceName string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return handle, nil
}
