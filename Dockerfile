# Base image for AArch64
FROM arm64v8/ubuntu:22.04

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Switch to a domestic mirror for Ubuntu ARM64 ports
RUN sed -i 's/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/ports.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get upgrade -y

# Install build dependencies
RUN apt-get install -y \
    build-essential \
    curl \
    pkg-config \
    libssl-dev \
    git \
    ca-certificates

# Configure and install Rust from a domestic mirror
ENV RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
ENV RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
ENV PATH="/root/.cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Configure crates.io to use a domestic mirror
RUN mkdir -p /root/.cargo && \
    echo '[source.crates-io]' > /root/.cargo/config.toml && \
    echo 'replace-with = "rsproxy"' >> /root/.cargo/config.toml && \
    echo '[source.rsproxy]' >> /root/.cargo/config.toml && \
    echo 'registry = "https://rsproxy.cn/crates.io-index"' >> /root/.cargo/config.toml

# Verify the Rust installation
RUN rustc --version && \
    cargo --version

# Test the Rust environment by building a Hello World project
RUN cargo new test-project && \
    cd test-project && \
    cargo build && \
    ./target/debug/test-project

# Set a working directory
WORKDIR /app

# Define a default command
CMD ["bash"]
