package main

import (
    "fmt"
    "os/exec"
)

func SetupIptables(port int, dev string) error {
    cmds := [][]string{
        {"iptables", "-A", "INPUT", "-i", dev, "-p", "udp", "--dport", fmt.Sprint(port), "-j", "ACCEPT"},
        {"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", dev, "-j", "MASQUERADE"},
    }

    for _, cmd := range cmds {
        if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
            return fmt.Errorf("iptables failed: %s: %v", string(out), err)
        }
    }
    return nil
}
