package main

import (
	"net"

	"github.com/vishvananda/netlink"
)

func AddFDBEntry(ifaceName string, mac net.HardwareAddr, dstIP net.IP) error {
	vxlanIf, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	fdb := &netlink.Neigh{
		LinkIndex:    vxlanIf.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           dstIP,
		HardwareAddr: mac,
		Family:       netlink.FAMILY_V4,
	}

	return netlink.NeighAdd(fdb)
}
