CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -m64 \
  -I/usr/include \
  -I/usr/include/x86_64-linux-gnu \
  -I/opt/libbpf/include \
  -I/opt/libbpf/include/uapi \
  --sysroot=/

all: ebpf/xdp.o

ebpf/xdp.o: ebpf/xdp_filter.c
	clang $(CFLAGS) -c $< -o $@