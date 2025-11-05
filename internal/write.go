package internal

import (
	"os"

	"github.com/google/gopacket"
)

func PacketsToBytes(packets []gopacket.Packet) []byte {
	var result []byte

	for _, packet := range packets {
		result = append(result, packet.Data()...)
	}
	return result
}

func WritePackets(filename string, packets []gopacket.Packet) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	bytes := PacketsToBytes(packets)
	_, err = file.Write(bytes)
	if err != nil {
		return err
	}
	return nil
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
