package main

import (
    "fmt"
    "os/exec"

    "github.com/songgao/water"
)

func CreateTUN(name string, cidr string) error {
    cfg := water.Config{DeviceType: water.TUN}
    cfg.Name = name
    tun, err := water.New(cfg)
    if err != nil {
        return err
    }

    cmds := [][]string{
        {"ip", "addr", "add", cidr, "dev", tun.Name()},
        {"ip", "link", "set", "dev", tun.Name(), "up"},
    }
    for _, cmd := range cmds {
        if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
            return fmt.Errorf("tun setup failed: %s: %v", string(out), err)
        }
    }
    return nil
}
