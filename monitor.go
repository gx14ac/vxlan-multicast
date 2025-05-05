package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type Event struct {
	VNI    uint32
	PktLen uint32
}

func StartMonitor(eventsMap *ebpf.Map) {
	rd, err := perf.NewReader(eventsMap, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	fmt.Println("Listening for eBPF events...")

	for {
		record, err := rd.Read()
		if err != nil {
			break
		}
		var evt Event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			fmt.Println("Failed to parse event:", err)
			continue
		}
		fmt.Printf("VNI: %d, Length: %d\n", evt.VNI, evt.PktLen)
	}
}
