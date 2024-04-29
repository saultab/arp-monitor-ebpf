FROM ubuntu:22.04   
WORKDIR /usr/src/app

RUN apt-get update
RUN apt-get install -y clang libelf-dev zlib1g-dev gcc-multilib make pkg-config llvm git
RUN git clone https://github.com/saultab/arp-monitor-ebpf.git && \
    cd arp-monitor-ebpf && \
    git submodule update --init --recursive && \
    cd ./libbpf/src  && \
    make  && \
    make install  && \
    ldconfig /usr/lib64  && \
    cd ../..  && \
    cd ./bpftool/src  && \
    make  && \
    make install  && \
    cd ../..  && \
    make

CMD ./arp-monitor-ebpf/ringbuf-reserve-submit eth0
