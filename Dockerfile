FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    libc6-dev \
    linux-libc-dev \
    libelf-dev \
    clang llvm gcc make \
    build-essential \
    git zlib1g-dev pkg-config gcc-multilib

RUN git clone --depth=1 https://github.com/libbpf/libbpf /opt/libbpf && \
    cd /opt/libbpf/src && make && make install_headers

WORKDIR /app
COPY . .

RUN make

CMD ["cp", "/app/ebpf/xdp.o", "/out/xdp.o"]