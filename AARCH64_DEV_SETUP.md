# 如何在 x86_64 主机上搭建 aarch64 Rust 开发环境

本文档旨在指导开发者如何在标准的 x86_64 架构主机上，利用 QEMU 和 Docker 快速搭建一个 aarch64 架构的 Rust 开发与测试环境。该环境基于 Ubuntu，并已预先配置好国内镜像源以加速软件下载和依赖拉取。

## 1. 环境要求

本指南基于 Arch Linux 系统编写，但同样适用于其他主流 Linux 发行版（如 Ubuntu, CentOS 等）。请确保你的系统上安装了以下核心软件：

- **Docker**: 用于容器化管理。
- **QEMU User Static**: 用于在 x86_64 主机上模拟执行 aarch64 等异构架构的程序。

### 在 Arch Linux 上安装

```bash
sudo pacman -S --noconfirm docker qemu-user-static
```

### 在 Debian/Ubuntu 上安装

```bash
sudo apt-get update
sudo apt-get install -y docker.io qemu-user-static
```

安装完成后，请启动并启用 Docker 服务：

```bash
sudo systemctl enable --now docker
```

## 2. 启用 binfmt_misc 多架构支持

为了让 Docker 能够无缝运行 aarch64 镜像，需要通过 `binfmt_misc` 注册 QEMU 解释器。执行以下命令即可自动完成配置：

```bash
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

该命令会注册多种架构的静态解释器，确保主机可以运行不同架构的二进制文件。

## 3. 创建项目文件

在你的工作目录下，创建以下两个核心文件：`Dockerfile` 和 `docker-compose.yml`。

### 3.1 Dockerfile

此 `Dockerfile` 用于构建 aarch64 架构的 Ubuntu 镜像，并内置了配置好国内源的 Rust 开发环境。

```dockerfile
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
```

### 3.2 docker-compose.yml

此文件用于方便地管理容器的生命周期，并挂载本地工作区，实现代码的实时同步。

```yaml
version: '3.8'

services:
  aarch64-dev:
    image: aarch64-rust-dev:latest
    container_name: aarch64-rust-dev-container
    platform: linux/arm64
    tty: true
    stdin_open: true
    restart: unless-stopped
    volumes:
      - ./workspace:/app
    working_dir: /app
```

## 4. 构建与运行

### 4.1 构建 Docker 镜像

在包含 `Dockerfile` 的目录下，执行以下命令构建镜像。`--platform` 参数是必需的，它告诉 Docker 我们要构建的目标平台是 `linux/arm64`。

```bash
docker build --platform linux/arm64 -t aarch64-rust-dev .
```

### 4.2 启动容器服务

使用 Docker Compose 在后台启动容器：

```bash
docker-compose up -d
```

## 5. 验证环境

环境启动后，我们可以进行最终验证，确保一切正常工作。

### 5.1 检查容器架构

执行以下命令，确认容器的体系架构是否为 `aarch64`：

```bash
docker-compose exec aarch64-dev uname -m
```

预期输出应为：
```
aarch64
```

### 5.2 测试 Rust 开发流程

1.  在本地创建一个 `workspace` 目录，它将被挂载到容器的 `/app` 目录。
    ```bash
    mkdir -p workspace
    ```

2.  在容器内创建一个新的 Rust 项目并运行它：
    ```bash
    docker-compose exec aarch64-dev bash -c "cargo new hello-aarch64 && cd hello-aarch64 && cargo run"
    ```
    如果一切顺利，你将看到 "Hello, world!" 输出。同时，你可以在本地的 `workspace/hello-aarch64` 目录下看到新创建的项目文件。

至此，你的 aarch64 Rust 开发环境已搭建完成！你可以直接在本地的 `workspace` 目录中修改代码，然后在容器中执行编译和测试命令。
