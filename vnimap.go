package main

import (
    "github.com/cilium/ebpf"
)

func AllowVNI(m *ebpf.Map, vni uint32) error {
    val := uint32(1)
    return m.Update(&vni, &val, ebpf.UpdateAny)
}

func RemoveVNI(m *ebpf.Map, vni uint32) error {
    return m.Delete(&vni)
}
