package main

import (
    "fmt"
    "github.com/vishvananda/netlink"
)

func CreateBridge(name string, members []string) error {
    br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}
    if err := netlink.LinkAdd(br); err != nil && err.Error() != "file exists" {
        return fmt.Errorf("bridge add failed: %v", err)
    }
    if err := netlink.LinkSetUp(br); err != nil {
        return fmt.Errorf("bridge up failed: %v", err)
    }

    for _, m := range members {
        l, err := netlink.LinkByName(m)
        if err != nil {
            return fmt.Errorf("member %s not found: %v", m, err)
        }
        if err := netlink.LinkSetMaster(l, br); err != nil {
            return fmt.Errorf("set master failed: %v", err)
        }
    }
    return nil
}
