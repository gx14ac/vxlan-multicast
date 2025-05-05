package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	ifaceName := "wg0"
	vni := uint32(100)
	port := 4789

	if err := AttachXDPWithVNI(ifaceName, vni); err != nil {
		log.Fatalf("failed to attach XDP: %v", err)
	}
	fmt.Println("XDP attached to", ifaceName)

	vxlanIf := "vxlan100"
	if err := CreateVXLAN(vxlanIf, vni, port, ifaceName); err != nil {
		log.Fatalf("failed to create vxlan interface: %v", err)
	}

	tunIf := "tun0"
	tunIP := "10.10.0.1/24"
	if err := CreateTUN(tunIf, tunIP); err != nil {
		log.Fatalf("failed to create TUN: %v", err)
	}

	bridgeIf := "br0"
	if err := CreateBridge(bridgeIf, []string{tunIf, vxlanIf}); err != nil {
		log.Fatalf("failed to setup bridge: %v", err)
	}

	if err := SetupIptables(port, ifaceName); err != nil {
		log.Fatalf("iptables error: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

// AttachXDPWithVNI attaches the XDP program to a network interface
// and inserts the specified VNI into the allowed_vni_map eBPF map.
func AttachXDPWithVNI(iface string, vni uint32) error {
	spec, err := ebpf.LoadCollectionSpec("xdp.o")
	if err != nil {
		return fmt.Errorf("failed to load XDP spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load XDP collection: %w", err)
	}

	prog := coll.Programs["filter_vxlan"]
	if prog == nil {
		return fmt.Errorf("XDP program 'filter_vxlan' not found")
	}

	m := coll.Maps["allowed_vni_map"]
	if m == nil {
		return fmt.Errorf("eBPF map 'allowed_vni_map' not found")
	}

	// 登録するVNIを許可
	val := uint32(1)
	if err := m.Put(vni, val); err != nil {
		return fmt.Errorf("failed to insert VNI into map: %w", err)
	}

	// ネットワークインターフェースを取得してアタッチ
	ifaceIndex := getIfaceIndex(iface)

	_, err = link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex,
		Flags:     link.XDPGenericMode, // XDPNativeMode が使える場合は変更可能
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP: %w", err)
	}

	fmt.Printf("XDP attached on %s with VNI %d\n", iface, vni)
	return nil
}

func getIfaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		panic(fmt.Sprintf("interface %s not found: %v", name, err))
	}
	return iface.Index
}
