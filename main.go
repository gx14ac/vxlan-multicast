// main.go
package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

func main() {
	createBridgeAndVXLAN()
	buildAndAttachXDP()
}

func createBridgeAndVXLAN() {
	// ブリッジ作成
	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br0"}}
	if err := netlink.LinkAdd(br); err != nil && !os.IsExist(err) {
		log.Fatal("bridge add:", err)
	}
	netlink.LinkSetUp(br)

	// VXLANインタフェース作成
	vxlan := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: "vxlan100"},
		VxlanId:      100,
		Group:        net.ParseIP("239.1.1.1"),
		VtepDevIndex: getIfIndex("eth0"),
		Port:         4789,
	}
	if err := netlink.LinkAdd(vxlan); err != nil && !os.IsExist(err) {
		log.Fatal("vxlan add:", err)
	}
	netlink.LinkSetUp(vxlan)
	netlink.LinkSetMasterByIndex(vxlan, br.Index)

	addr, _ := netlink.ParseAddr("10.10.10.1/24")
	netlink.AddrAdd(vxlan, addr)
}

func buildAndAttachXDP() {
	cmd := exec.Command("clang",
		"-O2", "-target", "bpf",
		"-c", "vxlan_xdp_filter.c",
		"-o", "vxlan_xdp_filter.o")
	var out bytes.Buffer
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		log.Fatalf("clang failed: %v\n%s", err, out.String())
	}

	spec, err := ebpf.LoadCollectionSpec("vxlan_xdp_filter.o")
	if err != nil {
		log.Fatal("load spec:", err)
	}

	objs := struct {
		Program *ebpf.Program `ebpf:"vxlan_filter"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal("load program:", err)
	}

	iface, _ := net.InterfaceByName("eth0")
	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Program,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("attach xdp:", err)
	}
	defer xdp.Close()

	fmt.Println("XDP program attached successfully.")
}

func getIfIndex(name string) int {
	link, err := netlink.LinkByName(name)
	if err != nil {
		log.Fatal("get if index:", err)
	}
	return link.Attrs().Index
}
