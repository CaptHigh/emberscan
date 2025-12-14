# EmberScan Docker Image
# Multi-stage build for optimized image size

# =============================================================================
# Stage 1: Build sasquatch and other tools
# =============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    && rm -rf /var/lib/apt/lists/*

# Build sasquatch for non-standard SquashFS
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch && \
    cd /tmp/sasquatch && \
    ./build.sh

# =============================================================================
# Stage 2: Main EmberScan image
# =============================================================================
FROM ubuntu:22.04

LABEL maintainer="EmberScan Team <security@emberscan.io>"
LABEL description="Automated Embedded Hardware Firmware Security Scanner"
LABEL version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Python
    python3 \
    python3-pip \
    python3-dev \
    # Firmware extraction
    binwalk \
    squashfs-tools \
    mtd-utils \
    gzip \
    bzip2 \
    xz-utils \
    p7zip-full \
    unzip \
    cpio \
    # QEMU emulation
    qemu-system-mips \
    qemu-system-arm \
    qemu-system-x86 \
    qemu-user-static \
    # Network scanning
    nmap \
    nikto \
    netcat-openbsd \
    tcpdump \
    # Binary analysis
    binutils \
    file \
    strings \
    # JFFS2 support
    liblzo2-2 \
    # Misc
    curl \
    wget \
    git \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Copy sasquatch from builder
COPY --from=builder /tmp/sasquatch/sasquatch /usr/local/bin/sasquatch

# Install jefferson for JFFS2
RUN pip3 install --no-cache-dir jefferson

# Create non-root user
RUN useradd -m -s /bin/bash emberscan && \
    echo "emberscan ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set working directory
WORKDIR /app

# Copy application
COPY . /app/

# Install EmberScan
RUN pip3 install --no-cache-dir -e .

# Create directories
RUN mkdir -p /data /app/workspace /app/kernels /app/reports && \
    chown -R emberscan:emberscan /app /data

# Download emulation kernels
RUN mkdir -p /app/kernels && \
    curl -L -o /app/kernels/vmlinux.mipsel \
        https://github.com/firmadyne/kernel-v4.1/raw/master/images/vmlinux.mipsel && \
    curl -L -o /app/kernels/vmlinux.mipseb \
        https://github.com/firmadyne/kernel-v4.1/raw/master/images/vmlinux.mipseb && \
    curl -L -o /app/kernels/zImage.armel \
        https://github.com/firmadyne/kernel-v4.1/raw/master/images/zImage.armel || true

# Switch to non-root user
USER emberscan

# Volume for firmware and reports
VOLUME ["/data"]

# Default command
ENTRYPOINT ["emberscan"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD emberscan --version || exit 1
