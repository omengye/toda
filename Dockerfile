# syntax=docker/dockerfile:experimental

FROM debian:buster-slim

ENV DEBIAN_FRONTEND noninteractive

ARG HTTPS_PROXY
ARG HTTP_PROXY

ENV http_proxy $HTTP_PROXY
ENV https_proxy $HTTPS_PROXY

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && sed -i 's/security.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt-get update && apt-get install build-essential curl git pkg-config libfuse-dev fuse -y && rm -rf /var/lib/apt/lists/*

RUN export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static && \
    export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly-2021-12-23 -y
ENV PATH "/root/.cargo/bin:${PATH}"

RUN if [ -n "$HTTP_PROXY" ]; then echo "[http]\n\
proxy = \"${HTTP_PROXY}\"\n\
"\
> /root/.cargo/config ; fi

COPY . /toda-build

WORKDIR /toda-build

ENV RUSTFLAGS "-Z relro-level=full"
RUN --mount=type=cache,target=/toda-build/target \
    --mount=type=cache,target=/root/.cargo/registry \
    RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup cargo build --release

RUN --mount=type=cache,target=/toda-build/target \
    cp /toda-build/target/release/toda /toda