package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func CreateVXLAN(name string, vni uint32, port int, parent string) error {
	parentLink, err := netlink.LinkByName(parent)
	if err != nil {
		return fmt.Errorf("parent device %s not found: %v", parent, err)
	}

	vx := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: name},
		VxlanId:      int(vni),
		VtepDevIndex: parentLink.Attrs().Index,
		Port:         port,
		Learning:     false,
	}

	if err := netlink.LinkAdd(vx); err != nil {
		return fmt.Errorf("vxlan link add failed: %v", err)
	}
	return netlink.LinkSetUp(vx)
}
