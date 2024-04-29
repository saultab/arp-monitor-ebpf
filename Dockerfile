 # Stage 1: Building
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y clang libelf-dev zlib1g-dev gcc-multilib make pkg-config llvm git

WORKDIR /usr/src/app
RUN git clone https://github.com/saultab/arp-monitor-ebpf.git

WORKDIR /usr/src/app/arp-monitor-ebpf
RUN git submodule update --init --recursive
RUN cd libbpf/src && make && make install && ldconfig /usr/lib64
RUN cd bpftool/src && make && make install
RUN make

# Stage 2: Runtime environment
FROM ubuntu:22.04

COPY --from=builder /usr/src/app/arp-monitor-ebpf/ringbuf-reserve-submit /usr/local/bin/
RUN apt-get update
RUN apt-get install -y libelf-dev && ldconfig

CMD ["ringbuf-reserve-submit", "eth0"]
