package main

import (
	"fmt"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

func CreateTUN(name string, cidr string) error {
	device, err := tun.CreateTUN(name, 1500)
	if err != nil {
		return fmt.Errorf("failed to create TUN: %w", err)
	}

	tunName, err := device.Name()
	if err != nil {
		return fmt.Errorf("failed to get tun name: %w", err)
	}

	fmt.Println("Created TUN device:", tunName)

	// LinuxコマンドでIP設定
	cmds := [][]string{
		{"ip", "addr", "add", cidr, "dev", tunName},
		{"ip", "link", "set", "dev", tunName, "up"},
	}

	for _, cmd := range cmds {
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute %v: %v\nOutput: %s", cmd, err, string(out))
		}
	}

	return nil
}
