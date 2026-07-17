# SPDX-License-Identifier: MIT
# Multi-stage build for arp-monitor-ebpf

# Stage 1: Build
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm llvm-dev \
    libelf-dev zlib1g-dev \
    gcc make pkg-config \
    linux-tools-common \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN git submodule update --init --recursive || true
RUN if [ -d libbpf/src ]; then \
        cd libbpf/src && make BUILD_STATIC_ONLY=1 && make install && ldconfig; \
    fi
RUN if [ -d bpftool/src ]; then \
        cd bpftool/src && make && make install; \
    fi
RUN make V=1

# Stage 2: Runtime
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/arp-monitor /usr/local/bin/arp-monitor

ENTRYPOINT ["arp-monitor"]
CMD ["-h"]
