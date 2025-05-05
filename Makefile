BPF_CLANG ?= clang
BPF_STRIP ?= llvm-strip

BPF_OBJ = xdp.o
BPF_SRC = xdp_filter.c

CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@
	$(BPF_STRIP) -g $@

clean:
	rm -f *.o
