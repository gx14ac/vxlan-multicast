## vxlan-multicast
test WireGuard Over L2

## build ebpf
temp build, change to nix build.

``` shell
docker build -t vxlan-xdp .
docker run --rm -v $(pwd)/out:/out vxlan-xdp
```

## TODO
- [] setting up vxlan and runetale
- [] testable vxlan machines by vm
