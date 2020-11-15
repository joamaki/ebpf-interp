package main

import (
	interp "ebpf-interp"
	"github.com/cilium/ebpf"
	//"github.com/cilium/ebpf/asm"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("usage: %v <program> <interface>\n", os.Args[0])
		os.Exit(1)
	}

	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(spec)

	prog := spec.Programs["test"]

	if handle, err := pcap.OpenLive(os.Args[2], 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		for {
			data, _, err := handle.ReadPacketData()
			switch {
			case err == io.EOF:
				return
			case err != nil:
				panic(err)
			default:
				// Run the test program for each packet to filter.
				machine := interp.NewMachine(prog.Instructions)

				// struct frame { uint64 len; uint8_t data[0]; }
				machine.StoreWord(0, uint64(len(data)))
				machine.SetMemory(8, data)

				result := machine.Run(0, false)

				if result == 1 {
					packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
					fmt.Println(packet)

				}

			}
		}
	}
}
